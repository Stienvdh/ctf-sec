#!/usr/bin/env python

import requests
import datetime
import json
import sys
from pathlib import Path

here = Path(__file__).parent.absolute()
repository_root = (here / ".." ).resolve()
sys.path.insert(0, str(repository_root))

import env

amp_url = env.AMP["host"]
amp_id = env.AMP["client_id"]
amp_key = env.AMP["api_key"]

def get_events(host):
    url = f"https://{amp_id}:{amp_key}@{amp_url}/v1/events?connector_guid[]={host}"
    headers = {}

    response = requests.get(url, headers)
    return response.json()["data"]

def get_all_events():
    url = f"https://{amp_id}:{amp_key}@{amp_url}/v1/events"
    headers = {}

    response = requests.get(url, headers)
    return response.json()["data"]

def get_event_type_id(name):
    url = f"https://{amp_id}:{amp_key}@{amp_url}/v1/event_types"
    headers = {}

    response = requests.get(url, headers)
    for type in response.json()["data"]:
        if type["name"] == name:
            return type["id"]
    return 0

def get_host_id(name):
    url = f"https://{amp_id}:{amp_key}@{amp_url}/v1/computers"
    headers = {}

    response = requests.get(url, headers)
    for c in response.json()["data"]:
        if c["hostname"] == name:
            return c["connector_guid"]
    return 0

def isolate_host(host):
    url = f"https://{amp_id}:{amp_key}@{amp_url}/v1/computers/{host}/isolation"
    headers = {}

    response = requests.put(url, headers)
    if response.status_code == 409:
        print("Host already isolated")

def unisolate_host(host):
    url = f"https://{amp_id}:{amp_key}@{amp_url}/v1/computers/{host}/isolation"

    response = requests.delete(url)
    if response.status_code == 409:
        print("Host already unisolated")

def investigate_file(hash):
    tg_host = env.THREATGRID.get("host")
    tg_api_key = env.THREATGRID.get("api_key")

    resp_tg = requests.get(f"https://{tg_host}/api/v2/search/submissions?q={hash}&api_key={tg_api_key}").json()["data"]
    if len(resp_tg["items"]) > 0:
        return resp_tg["items"][0]["item"]["sample"]
    else:
        return 0

def find_domains(id):
    tg_host = env.THREATGRID.get("host")
    tg_api_key = env.THREATGRID.get("api_key")

    resp_tg = requests.get(f"https://{tg_host}/api/v2/samples/feeds/domains?sample={id}&api_key={tg_api_key}").json()["data"]
    
    doms = []
    for d in resp_tg["items"]:
        doms += [d["domain"]]
    return doms

if __name__ == "__main__":
    # EXAMPLE_HOST = "Demo_AMP_Threat_Audit"
    # EVENTS = get_events(get_host_id(EXAMPLE_HOST))
    EVENTS = get_all_events()

    malicious_events = []
    for e in EVENTS:
        if "event_type" in e and e["event_type"] == "Executed malware":
            malicious_events += [{"host" : e["connector_guid"], "file" : e["file"]["identity"]["sha256"]}]
    
    DOMAINS = []
    for e in malicious_events:
        isolate_host(e["host"])
        tg_id = investigate_file(e["file"])
        DOMAINS += find_domains(tg_id)

    DOMAINS = set(DOMAINS)
    with open("stage2.txt", "w") as f:
        for d in DOMAINS:
            f.write(f"{d}\n")
    
    # Cleanup
    for e in malicious_events:
        unisolate_host(e["host"])
    
