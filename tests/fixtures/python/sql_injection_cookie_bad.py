from flask import request


def query(cursor):
    statement = f"SELECT * FROM users WHERE id={request.cookies.get('id')}"
    cursor.execute(statement)
