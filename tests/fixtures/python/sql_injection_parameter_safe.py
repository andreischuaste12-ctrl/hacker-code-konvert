from flask import request


def query(cursor):
    cursor.execute("SELECT * FROM users WHERE id=%s", (request.cookies.get("id"),))
