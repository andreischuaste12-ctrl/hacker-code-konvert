from flask import request


def download():
    with open("/srv/files/" + request.args.get("name")) as handle:
        return handle.read()
