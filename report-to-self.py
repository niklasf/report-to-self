#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Self hosted endpoint for HTTP Report-To and NEL."""

import argparse
import aiohttp.web
import datetime
import os
import os.path
import uuid

class Api:
    def __init__(self, config):
        self.config = config

    def log(self, line):
        print(line)
        if self.config.log is not None:
            print(line, file=self.config.log)

    async def forensics(self, report_type, req):
        if not self.config.forensics:
            return

        path = os.path.join(
            self.config.forensics,
            datetime.date.today().strftime('%Y-%m-%d'),
            report_type,
            str(uuid.uuid4()))

        os.makedirs(os.path.dirname(path))

        with open(path, "w") as f:
            print(req.method, req.url, file=f)
            print(file=f)
            for header, value in req.headers.items():
                print(header, value, sep=": ", file=f)
            print(file=f)
            print(await req.text(), file=f)

    async def handle_ct(self, req):
        self.log("nel,type=tls.cert.ct,value=1")
        await self.forensics("tls.cert.ct", req)
        raise aiohttp.web.HTTPNoContent

    async def handle_default(self, req):
        self.log("nel,type=default,value=1")
        await self.forensics("default", req)
        raise aiohttp.web.HTTPNoContent


def make_app(config):
    api = Api(config)

    app = aiohttp.web.Application()
    app.add_routes([
        aiohttp.web.post("/report/ct", api.handle_ct),
        aiohttp.web.post("/report/default", api.handle_default),
    ])

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=argparse.FileType("a"), help="Also log to this file instead of only stdout")
    parser.add_argument("--forensics", help="Base directory for forensic request dumps")
    parser.add_argument("--port", default=9390, help="Web server port")
    config = parser.parse_args()
    aiohttp.web.run_app(make_app(config), port=config.port)
