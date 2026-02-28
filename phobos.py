#!/usr/bin/env python3

#
# Importing additional libraries
#

import requests
import time
import datetime 
import sys
import os
import re
import matplotlib.pyplot as plt
import numpy as np
from dotenv import main
from pprint import pprint


main.load_dotenv('config.env')

API_KEY = os.getenv('VT_API_KEY')
print(API_KEY)



if len(sys.argv) < 2:
    exit("Phobos.py requires a URL as an argument to run.\nUsage: phobos.py url")

URL_TO_SCAN = sys.argv[1]   # 
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

def calculate_score(URL, reputation,harmless_score,malicious_score):
    print("The overall score is based on a range from -100 to +100")
    if reputation > 50:
        rep_score = 'Good'
    if reputation < 49:
        rep_score = 'Poor'
    if reputation > 0:
        rep_score = 'Bad'
    print(f"The site {URL} has a Reputation Score of {rep_score}")
    if harmless_score > 50:
        harm_score = 'Harmless'
        print(f"It's Threat Rating is: {harm_score}")
    if malicious_score > 1:
        harm_score = 'Threatening'
        print("The site is potentially mailicious with a Malicious Score of: {malicious_score}")


def generate_chart(reputation, harmless_score, malicious_score):
    #Using Matplotlib to create a plot

    repute_score = reputation
    reputation_rating = [-100, -50, 0, 50, 100]

    cats = ['Reputation', 'Harmless', 'Malicious']      #Categories
    vals = [repute_score, harmless_score, malicious_score]

    w, x = 0.4, np.arange(len(cats))
    fig, ax = plt.subplots()

    ax.bar(x - w/2, vals, width=w, )
    
    ax.set_xticks(x)
    ax.set_xticklabels(cats)
    ax.set_ylabel('Score')
    ax.set_title('Score Breakdown')
    #ax.legend(repute_score, harmless_score, malicious_score)

    plt.show()
    print("Generated a Bar Chart called reputation.png")

    

# ======================
# MAIN EXECUTION
# ======================

def main():
    """Main execution function"""
    try:
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

        URL = attributes.get('url', 0)
        reputation =  attributes.get('reputation', 0)
        source_category = attributes.get("categories", {}.items())

        harmless_score = stats.get('harmless') 
        malicious_score = stats.get('malicious')
        suspicion_score = stats.get('suspicious')
        undetection_score = stats.get('undetected')


        # 6 Print Summary Values - Note: From here on we will be taking values already assembled, and after the print statements, we can then build a graph report       
        print("\n=== URL INFORMATION ===")
        print(f"URL: ", URL)
        print(f"Reputation: ", reputation)      
        print(f"Harmless score: ", harmless_score)
        print(f"Malicious Score: ", malicious_score)
        print(f"Suspicion Score: ", suspicion_score)
        print(f"Undetection Score: ", undetection_score)

        print("\n=== CATEGORY ===")
        for source, category in attributes.get("categories", {}).items():
            print(f"{source}: {category}")

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


        calculate_score(URL, reputation,harmless_score,malicious_score)

        generate_chart(reputation, harmless_score, malicious_score) 


        print("\n[✓] Analysis complete.")

    except Exception as e:
        print(f"Error during execution: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
