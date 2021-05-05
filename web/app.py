import asyncio
import logging

import aiohttp.web_response
from aiohttp import web

from backend.db.db import get_dangerous_domains, export_to_csv
from backend.domains.checker import find_dangerous_domains

logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s: %(message)s",
    level=logging.DEBUG,
    datefmt="%d-%b-%y %H:%M:%S",
    filename=".log"
)
logger = logging.getLogger(__name__)
routes = web.RouteTableDef()


async def search_for_dangerous_domains(app: web.Application):
    app["find_dangerous_domains"] = asyncio.create_task(
        find_dangerous_domains()
    )


async def cleanup_background_tasks(app):
    app["find_dangerous_domains"].cancel()
    await app["find_dangerous_domains"]


@routes.get("/api/dangerous_domains")
async def output_current_results(request: web.Request):
    found_dangerous_domains = await get_dangerous_domains()
    output_format = request.rel_url.query.get("fmt", "")

    if output_format == "json":
        return aiohttp.web_response.json_response(found_dangerous_domains)
    elif output_format == "csv":
        await export_to_csv()
        return aiohttp.web_response.Response(
            text="http://localhost/assets/csv/dangerous_domains.csv"
        )


app = web.Application()
app.add_routes(routes)
# app.on_startup.append(search_for_dangerous_domains)
# app.on_cleanup.append(cleanup_background_tasks)
