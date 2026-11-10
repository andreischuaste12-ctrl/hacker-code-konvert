import requests
from flask import request


def preview():
    return requests.get(request.args.get("url"), timeout=5).text
