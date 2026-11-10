def fetch(session, url):
    return session.post(url, timeout=10)
