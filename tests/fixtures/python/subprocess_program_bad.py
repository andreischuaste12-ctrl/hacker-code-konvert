import subprocess

from flask import request


def handler():
    subprocess.run([request.args.get("tool"), "--version"])
