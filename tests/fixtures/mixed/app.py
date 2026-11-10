import marshal
import pickle
import subprocess
import subprocess as sp
from os import system

import requests
import yaml
from flask import request


def h1(): system(request.args.get("c"))                     # aliased import
def h2(): sp.run(request.args.get("c"), shell=True)         # module alias
def h3(): pickle.load(open(request.args.get("f"), "rb"))    # load not loads
def h4(): requests.post("https://x", verify=False)          # post not get
def h5(): yaml.unsafe_load(request.data)
def h6(): subprocess.run(["sh", "-c", request.args.get("c")])
def h7(): open("/srv/" + request.args.get("p")).read()      # path traversal
def h8(): requests.get(request.args.get("u"))               # SSRF
def h9(cur): cur.execute("SELECT * FROM t WHERE id=%s" % request.args.get("i"))
def h10(cur):
    q = f"SELECT * FROM t WHERE id={request.cookies.get('i')}"   # cookie source
    cur.execute(q)
def h11(): __import__("os").system(request.headers.get("X"))
def h12(): marshal.loads(request.data)
PASSWORD = "hunter2hunter2"
db_password = "hunter2hunter2"
