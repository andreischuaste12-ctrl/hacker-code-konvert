def query(cursor):
    cursor.execute("SELECT * FROM users WHERE id=%s", (input(),))
