# Clean fixture: the safe counterparts of vulnerable_app.py. Must produce no findings.
import hashlib
import os
import secrets
import subprocess

import requests
import yaml

API_KEY = os.environ["API_KEY"]


def run(args):
    return subprocess.run(["ls", "-l", *args], check=True)


def find_user(cur, name):
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))


def fetch(url):
    return requests.get(url, timeout=10)


def digest(pw, salt):
    return hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1)


def config(text):
    return yaml.load(text, Loader=yaml.SafeLoader)


def new_token():
    return secrets.token_urlsafe(32)


evaluate_score = 3  # identifier merely containing the word, not a call
