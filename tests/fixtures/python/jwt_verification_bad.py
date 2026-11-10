import jwt


def claims(token):
    return jwt.decode(token, options={"verify_signature": False})
