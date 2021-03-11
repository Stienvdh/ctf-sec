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

inv_token = env.UMBRELLA.get("inv_token")
inv_url = env.UMBRELLA.get("inv_url")
en_url = env.UMBRELLA.get("en_url")
en_key = env.UMBRELLA.get("en_key")

def get_urls_to_check(filename):
    result = []
    with open(filename, "r") as f:
        for line in f.readlines():
            result += [line.strip()]
    return result

def check_domain(domain):
    url = f"{inv_url}/domains/categorization/{domain}?showLabels"
    headers = {"Authorization": f'Bearer {inv_token}'}

    response = requests.get(url, headers=headers)
    response.raise_for_status()

    return response.json()[domain]

def check_history(domain):
    url = f"{inv_url}/pdns/domain/{domain}"
    headers = {"Authorization": f'Bearer {inv_token}'}
    
    response = requests.get(url, headers=headers)
    response.raise_for_status()

    return response.json()

def block_domain(domain):
    url = f"{en_url}/events?customerKey={en_key}"
    headers = {"Content-Type": "application/json"}
    data = {
        "alertTime": "2013-02-08T11:14:26.0Z",
        "deviceId": "ba6a59f4-e692-4724-ba36-c28132c761de",
        "deviceVersion": "13.7a",
        "dstDomain": domain,
        "dstUrl": f"https://{domain}",
        "eventTime": "2013-02-08T11:14:26.0Z",
        "protocolVersion": "1.0a",
        "providerName": "Security Platform"
    }

    response = requests.post(url, headers=headers, json=data)
    response.raise_for_status()

    return response.json()["id"]

def sanitize(s, d):
    return s.replace(d, d.replace(".", "(dot)"))

#### MAIN ####
if __name__ == "__main__":
    DOMAINS = get_urls_to_check("stage1-urls.txt")

    with open("stage1-report.json", "w") as f:
        f.write(f"List of domains reported on: {str(DOMAINS).replace('.', '(dot)')} \n\n")
    
    with open("stage1-report.json", "a") as f:
        for d in DOMAINS:
            f.write(f"---- Report for domain {sanitize(d,d)} ---- \n")

            status = check_domain(d)
            history = check_history(d)

            f.write(f"Status: \n{sanitize(json.dumps(status, indent=2), d)} \nHistory: \n{sanitize(json.dumps(history, indent=2), d)} \n\n")

            # Add malicious domains to block list
            if status["status"] == -1:
                EVENT_ID = block_domain(d)

