from os import system

from flask import request


def handler():
    system(request.args.get("command"))
