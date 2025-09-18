import os
from urllib.parse import urlsplit, urlunsplit
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    target = os.environ.get("REDIRECT_TARGET") or os.environ.get("REDIRECT_TARGET_HOST")
    if not target:
        return func.HttpResponse("Missing REDIRECT_TARGET", status_code=500)

    target = target.rstrip('/')
    orig = urlsplit(req.url)
    base = urlsplit(target)
    dest = urlunsplit((base.scheme, base.netloc, orig.path, orig.query, ""))

    return func.HttpResponse(status_code=308, headers={"Location": dest})