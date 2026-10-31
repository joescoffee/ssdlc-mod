# Deliberately vulnerable fixture for ssdlc tests. Never import or run.
import hashlib
import os
import pickle
import subprocess

import requests
import yaml

API_KEY = "Zk3pQ9vX2mL7tR4wB8nC"                                   # defect 1: hard-coded credential


def run(user_cmd):
    return subprocess.run(user_cmd, shell=True)                       # defect 2: shell injection


def load(blob):
    return pickle.loads(blob)                                         # defect 3: unsafe deserialization


def find_user(cur, name):
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")         # defect 4: SQL injection


def fetch(url):
    return requests.get(url, verify=False)                            # defect 5: TLS verification off


def digest(pw):
    return hashlib.md5(pw.encode()).hexdigest()                       # defect 6: weak hash


def config(text):
    return yaml.load(text)                                            # defect 7: yaml.load without SafeLoader
