import subprocess

from flask import request


def handler():
    subprocess.run(["convert", "--", request.args.get("name")])
