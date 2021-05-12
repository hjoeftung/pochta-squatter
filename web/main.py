import asyncio
from multiprocessing import Process
import logging

import aiohttp.web_response
from aiohttp import web

from backend.db.db_utils import get_dangerous_domains_list, whitelist_url, get_url_by_id
from backend.domains.domains_checker import find_dangerous_domains

logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s: %(message)s",
    level=logging.DEBUG,
    datefmt="%d-%b-%y %H:%M:%S",
    filename=".log"
)
logger = logging.getLogger(__name__)
routes = web.RouteTableDef()


async def run_background_search():
    while True:
        await find_dangerous_domains()

        # Schedule next search in 24 hours
        await asyncio.sleep(86400)


async def set_up_background_tasks(app: web.Application):
    app["run_background_search"] = asyncio.create_task(run_background_search())


async def cleanup_background_tasks(app):
    app["run_background_search"].cancel()
    await app["run_background_search"]


@routes.get("/api/dangerous-urls")
async def output_current_results(request: web.Request):
    found_dangerous_domains = await get_dangerous_domains_list()
    return aiohttp.web_response.json_response(found_dangerous_domains)


@routes.patch("/api/dangerous-urls/{url_id}")
async def do_whitelist_url(request: web.Request):
    url_id = request.match_info.get("url_id", "")
    logger.debug(f"url_id = {url_id}")
    url_to_whitelist = await get_url_by_id(url_id)
    if url_to_whitelist:
        await whitelist_url(url_to_whitelist)
        logger.info(f"Url {url_to_whitelist} has been whitelisted")
        return aiohttp.web_response.Response(
            status=200, text=f"{url_to_whitelist}"
        )
    else:
        return aiohttp.web_response.Response(
            status=404, text=f"Url with the {url_id} id has not been found"
        )


app = web.Application()
app.add_routes(routes)
app.on_startup.append(set_up_background_tasks)
app.on_cleanup.append(cleanup_background_tasks)
