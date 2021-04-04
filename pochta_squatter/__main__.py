#! usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import json
import logging

from aiohttp import web

from pochta_squatter.db.db import get_dangerous_domains

# Initializing logger
logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s: %(message)s",
    level=logging.DEBUG,
    datefmt="%d-%b-%y %H:%M:%S",
)
logger = logging.getLogger(__name__)
app = web.Application()


async def get_current_results(request):
    dangerous_domains = await get_dangerous_domains()
    return web.Response(text=json.dumps(dangerous_domains))


if __name__ == "__main__":
    app.add_routes([web.get('/', get_current_results)])
    web.run_app(app)
