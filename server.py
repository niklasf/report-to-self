import argparse
import aiohttp.web

async def dump_request(req):
    dump = [req.method, " ", str(req.url), "\n"]
    dump.append("\n")
    for header, value in req.headers.items():
        dump.extend([header, ": ", value, "\n"])
    dump.append("\n")
    dump.append(await req.text())
    return dump

async def handle_ct(req):
    print("nel,type=tls.cert.ct,value=1")
    raise aiohttp.web.HTTPNoContent

app = aiohttp.web.Application()
app.add_routes([
    aiohttp.web.post("/ct", handle_ct)
])

if __name__ == "__main__":
    aiohttp.web.run_app(app)
