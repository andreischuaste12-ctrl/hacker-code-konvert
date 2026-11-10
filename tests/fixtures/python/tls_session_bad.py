import ssl


def fetch(session, url):
    context = ssl._create_unverified_context()
    return session.post(url, verify=False), context
