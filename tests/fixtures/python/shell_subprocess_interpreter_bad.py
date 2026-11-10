import subprocess

from flask import request


def handler():
    subprocess.run(["sh", "-c", request.form["command"]])
