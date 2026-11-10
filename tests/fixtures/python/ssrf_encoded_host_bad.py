import urllib.parse

import requests
from flask import request

requests.get('http://' + urllib.parse.quote(request.args['host']))
