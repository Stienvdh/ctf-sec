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

ctr_host = env.THREATRESPONSE.get("ctr_host")
ctr_client_id = env.THREATRESPONSE.get("ctr_client_id")
ctr_client_pwd = env.THREATRESPONSE.get("ctr_client_pwd")

AUTH_TOKEN = ""

def get_auth_token():
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
        }

    resp_ctr = requests.post(f"https://{ctr_host}/iroh/oauth2/token", headers=headers, auth=(ctr_client_id, ctr_client_pwd), data='grant_type=client_credentials')
    return resp_ctr.json()["access_token"]

def ctr_inspect(hash):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {AUTH_TOKEN}'
        }
    
    data = {
        "content": f"suspicious hash is {hash}"
    }

    resp_ctr = requests.post(f"https://{ctr_host}/iroh/iroh-inspect/inspect", headers=headers, json=data)
    return resp_ctr.json()

def ctr_enrich(observables):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {AUTH_TOKEN}'
        }

    resp_ctr1 = requests.post(f"https://{ctr_host}/iroh/iroh-enrich/deliberate/observables", headers=headers, json=observables)
    resp_ctr2 = requests.post(f"https://{ctr_host}/iroh/iroh-enrich/observe/observables", headers=headers, json=observables)
    resp_ctr3 = requests.post(f"https://{ctr_host}/iroh/iroh-enrich/refer/observables", headers=headers, json=observables)

    return resp_ctr1.json()["data"] + resp_ctr2.json()["data"] + resp_ctr3.json()["data"]

def ctr_respond(observables):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': f'Bearer {AUTH_TOKEN}'
        }

    resp_ctr1 = requests.post(f"https://{ctr_host}/iroh/iroh-response/respond/observables", headers=headers, json=observables)

    trigger_url = resp_ctr1.json()["data"][0]["url"]
    trigger_resp = requests.post(f"https://{ctr_host}/iroh/iroh-response{trigger_url}", headers=headers, json=observables)
    trigger_resp.raise_for_status()

    return resp_ctr1.json()["data"]

if __name__ == "__main__":
    EXAMPLE_SHA = "b1380fd95bc5c0729738dcda2696aa0a7c6ee97a93d992931ce717a0df523967"

    AUTH_TOKEN = get_auth_token()
    OBSERVABLES = ctr_inspect(EXAMPLE_SHA)
    
    with open("stage3.json", 'w') as f:
        f.write(f"Information about the hash: \n{json.dumps(ctr_enrich(OBSERVABLES), indent=2)} \n\n")
        f.write(f"Actions taken: \n{json.dumps(ctr_respond(OBSERVABLES), indent=2)}")


