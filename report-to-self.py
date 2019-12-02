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
        if self.config.log is None:
            print(line, flush=True)
        else:
            print(line, file=self.config.log, flush=True)

    async def options(self, req):
        return aiohttp.web.Response(status=204, headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "OPTIONS, POST",
            "Access-Control-Allow-Headers": req.headers.get("Access-Control-Request-Headers", "content-type"),
        })

    async def forensics(self, report_type, req):
        if not self.config.forensics:
            return

        path = os.path.join(
            self.config.forensics,
            datetime.date.today().strftime('%Y-%m-%d'),
            report_type,
            str(uuid.uuid4()))

        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))

        with open(path, "w") as f:
            print(req.method, req.url, file=f)
            print(file=f)
            for header, value in req.headers.items():
                print(header, value, sep=": ", file=f)
            print(file=f)

            text = await req.text()
            try:
                text = json.dumps(json.loads(text), indent=2)
            except ValueError:
                pass
            print(await req.text(), file=f)

    async def handle_ct(self, req):
        self.log("nel,type=tls.cert.ct,value=1")
        await self.forensics("tls.cert.ct", req)
        raise aiohttp.web.HTTPOk

    async def handle_default(self, req):
        try:
            body = await req.json()
        except ValueError:
            raise aiohttp.web.HTTPBadRequest

        if not isinstance(body, list):
            raise aiohttp.web.HTTPBadRequest

        for item in body:
            if not isinstance(item, dict):
                raise aiohttp.web.HTTPBadRequest

            report_type = item.get("type", "unknown")
            body = item.get("body", {})
            source_file = body.get("sourceFile")
            if isinstance(source_file, str) and source_file.startswith("chrome-extension://"):
                continue

            self.log("nel,type={},value=1".format(report_type))
            await self.forensics(report_type, req)

        raise aiohttp.web.HTTPOk

    async def handle_dmarc(self, req):
        self.log("nel,type=dmarc,value=1")
        await self.forensics("dmarc", req)
        raise aiohttp.web.HTTPOk


def make_app(config):
    api = Api(config)

    app = aiohttp.web.Application()
    app.add_routes([
        aiohttp.web.options("/report/ct", api.options),
        aiohttp.web.options("/report/default", api.options),
        aiohttp.web.options("/report/dmarc", api.options),
        aiohttp.web.post("/report/ct", api.handle_ct),
        aiohttp.web.post("/report/default", api.handle_default),
        aiohttp.web.post("/report/dmarc", api.handle_dmarc),
    ])

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=argparse.FileType("a"), help="Also log to this file instead of only stdout")
    parser.add_argument("--forensics", help="Base directory for forensic request dumps")
    parser.add_argument("--port", default=9390, help="Web server port")
    config = parser.parse_args()
    aiohttp.web.run_app(make_app(config), port=config.port)
