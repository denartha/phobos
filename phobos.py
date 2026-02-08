#!/usr/bin/env python3



import requests
import time
import datetime 
import sys
from dotenv import main
import os

main.load_dotenv('config.env')

API_KEY = os.getenv('VT_API_KEY')
print(API_KEY)



URL_TO_SCAN = sys.argv[1]

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

def convert_from_epoch(epoch):
    value = datetime.datetime.fromtimestamp(epoch.pop())
    return value.strftime('%Y-%m-%d %H:%M:%S')


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

# 5. Assemble Summary Values

URL = {attributes.get('url', 0)}
URL = str(URL)
reputation =  {attributes.get('reputation', 0)}

first_seen_epoch = {attributes.get('first_submission_date', 0)}
last_checked_epoch = {attributes.get('last_analysis_date', 0)}

first_seen = convert_from_epoch(first_seen_epoch)
last_checked = convert_from_epoch(last_checked_epoch)

# 6 Print Summary Values       
print("\n=== URL INFORMATION ===")
print(f"URL: { URL }")
print(f"Reputation: {reputation}")      
print(f"First Seen: {first_seen}")
print(f"Last Analysis: {last_checked}")




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
