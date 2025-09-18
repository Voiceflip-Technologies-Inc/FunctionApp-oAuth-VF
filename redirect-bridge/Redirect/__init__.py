import os
from urllib.parse import urlsplit, urlunsplit
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    target = os.environ.get("REDIRECT_TARGET") or os.environ.get("REDIRECT_TARGET_HOST")
    if not target:
        return func.HttpResponse("Missing REDIRECT_TARGET", status_code=500)

    # Normalize target base (no trailing slash)
    target = target.rstrip('/')

    # Rebuild destination URL: keep original path+query, replace scheme+host
    orig = urlsplit(req.url)
    base = urlsplit(target)
    dest = urlunsplit((base.scheme, base.netloc, orig.path, orig.query, ""))

    # 308 to preserve method + body on POST/PUT/PATCH
    return func.HttpResponse(status_code=308, headers={"Location": dest})