import os

from flask import request


def download():
    with open("/srv/files/" + os.path.basename(request.args.get("name"))) as handle:
        return handle.read()
