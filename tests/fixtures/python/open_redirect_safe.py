from flask import redirect, url_for


def leave():
    return redirect(url_for("index"))
