#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Self hosted endpoint for HTTP Report-To and NEL."""

import argparse
import aiohttp.web

class Api:
    def __init__(self, config):
        self.config = config

    def log(self, line):
        print(line)
        if self.config.log is not None:
            print(line, file=self.config.log)

    async def dump_request(self, req):
        dump = [req.method, " ", str(req.url), "\n"]
        dump.append("\n")
        for header, value in req.headers.items():
            dump.extend([header, ": ", value, "\n"])
        dump.append("\n")
        dump.append(await req.text())
        return dump

    async def handle_ct(self, req):
        self.log("nel,type=tls.cert.ct,value=1")
        raise aiohttp.web.HTTPNoContent


def make_app(config):
    api = Api(config)

    app = aiohttp.web.Application()
    app.add_routes([
        aiohttp.web.post("/ct", api.handle_ct)
    ])

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=argparse.FileType("a"), help="Also log to this file instead of only stdout")
    parser.add_argument("--forensics", help="Base directory for forensic request dumps")
    aiohttp.web.run_app(make_app(parser.parse_args()))
