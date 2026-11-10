import requests
from flask import request


def preview():
    return requests.get("https://example.invalid/status", params={"q": request.args.get("q")}, timeout=5)
