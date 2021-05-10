import asyncio
import logging

import aiohttp.web_response
from aiohttp import web

from backend.db.db_utils import get_dangerous_domains_list, export_to_csv
from backend.domains.domains_checker import find_dangerous_domains

logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s: %(message)s",
    level=logging.DEBUG,
    datefmt="%d-%b-%y %H:%M:%S",
    filename=".log"
)
logger = logging.getLogger(__name__)
routes = web.RouteTableDef()


async def set_up_background_tasks(app: web.Application):
    app["find_dangerous_domains"] = await find_dangerous_domains()
    app["export_domains_to_csv"] = await export_to_csv()


async def cleanup_background_tasks(app):
    app["find_dangerous_domains"].cancel()
    await app["find_dangerous_domains"]
    app["export_domains_to_csv"].cancel()
    await app["export_domains_to_csv"]


@routes.get("/api/dangerous_domains")
async def output_current_results(request: web.Request):
    found_dangerous_domains = await get_dangerous_domains_list()
    return aiohttp.web_response.json_response(found_dangerous_domains)


app = web.Application()
app.add_routes(routes)
# app.on_startup.append(set_up_background_tasks)
# app.on_cleanup.append(cleanup_background_tasks)
