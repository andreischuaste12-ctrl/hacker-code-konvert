from flask import render_template, request


def greet():
    return render_template("greet.html", name=request.args.get("name"))
