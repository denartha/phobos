#!/usr/bin/env python3

# API Key: 9a71ddfbf6256a950c4562fa12af7f3fc1bdb4c60eaa0c0d0f8274688f8f2947


import requests
import time
from datetime import datetime

API_KEY = "9a71ddfbf6256a950c4562fa12af7f3fc1bdb4c60eaa0c0d0f8274688f8f2947"
URL_TO_SCAN = "https://boards.ie"

HEADERS = {
    "x-apikey": API_KEY
}

def submit_url(url):
    submit_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(
        submit_url,
        headers=HEADERS,
        data={"url": url}
    )
    response.raise_for_status()
    return response.json()["data"]["id"]

def get_analysis(analysis_id):
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    response = requests.get(analysis_url, headers=HEADERS)
    response.raise_for_status()
    return response.json()

def get_url_details(url_id):
    url_details_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    response = requests.get(url_details_url, headers=HEADERS)
    response.raise_for_status()
    return response.json()

# 1. Submit URL
analysis_id = submit_url(URL_TO_SCAN)
print(f"[+] URL submitted")
print(f"[+] Analysis ID: {analysis_id}")

# VirusTotal requires base64 URL ID (strip '=')
url_id = analysis_id.split("-")[1]

# 2. Wait for analysis
time.sleep(6)

# 3. Fetch analysis results
analysis_data = get_analysis(analysis_id)
stats = analysis_data["data"]["attributes"]["stats"]
results = analysis_data["data"]["attributes"]["results"]

# 4. Fetch URL details
details_data = get_url_details(url_id)
attributes = details_data["data"]["attributes"]

# 5. Print Summary
print("\n=== URL INFORMATION ===")
print(f"URL:             {attributes.get('url')}")
print(f"Reputation:      {attributes.get('reputation')}")
print(f"First Seen:      {datetime.utcfromtimestamp(attributes.get('first_submission_date', 0))}")
print(f"Last Analysis:   {datetime.utcfromtimestamp(attributes.get('last_analysis_date', 0))}")

print("\n=== CATEGORY ===")
for source, category in attributes.get("categories", {}).items():
    print(f"{source}: {category}")

print("\n=== ANALYSIS STATS ===")
print(f"Harmless:   {stats.get('harmless')}")
print(f"Malicious:  {stats.get('malicious')}")
print(f"Suspicious: {stats.get('suspicious')}")
print(f"Undetected: {stats.get('undetected')}")

print("\n=== ENGINE DETECTIONS ===")
for engine, result in results.items():
    category = result["category"]
    if category in ("malicious", "suspicious"):
        print(f"{engine:<25} {category.upper():<10} {result.get('result')}")

if not any(r["category"] in ("malicious", "suspicious") for r in results.values()):
    print("No malicious or suspicious detections found.")

print("\n=== ADDITIONAL DETAILS ===")
print(f"Times Submitted: {attributes.get('times_submitted')}")
print(f"Threat Names:    {attributes.get('threat_names', [])}")
print(f"Redirections:    {attributes.get('redirection_chain', [])}")

print("\n[✓] Analysis complete.")
