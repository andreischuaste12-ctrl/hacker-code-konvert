from flask import redirect, request


def leave():
    return redirect(request.args.get("next"))
