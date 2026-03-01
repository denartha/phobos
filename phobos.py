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

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate
from reportlab.lib import colors
from reportlab.platypus import Frame
from reportlab.platypus import KeepInFrame
from reportlab.platypus import Spacer
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.platypus import FrameBreak
from reportlab.platypus import PageBreak
from reportlab.platypus import BaseDocTemplate
from reportlab.platypus import Frame
from reportlab.platypus import PageTemplate
from openai import OpenAI
from dotenv import load_dotenv



load_dotenv('config.env')

API_KEY = os.getenv('VT_API_KEY')

def get_chatgpt_summary(URL, reputation, harmless_score, malicious_score):
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    prompt = f"""
    You are a cybersecurity analyst.

    Summarise the following threat intelligence findings into a clear,
    professional executive summary suitable for inclusion in a PDF report.

    URL: {URL}
    Reputation Score: {reputation}
    Harmless Score: {harmless_score}
    Malicious Score: {malicious_score}

    Provide:
    - A short executive summary
    - A clear risk assessment
    - Recommended action for users
    """

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a professional cybersecurity threat analyst."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.3,
    )

    return response.choices[0].message.content.strip()


def wrap_text(text, canvas_obj, max_width):
    """Helper function to wrap text within PDF margins"""
    lines = []
    words = text.split()
    line = ""

    for word in words:
        test_line = f"{line} {word}".strip()
        if canvas_obj.stringWidth(test_line, "Helvetica", 12) <= max_width:
            line = test_line
        else:
            lines.append(line)
            line = word

    if line:
        lines.append(line)

    return lines


def create_threat_report_pdf(URL, reputation, harmless_score, malicious_score,
                             image_path="reputation.png",
                             path="Threat_report.pdf"):

    # 🔹 Step 1: Get AI Summary
    ai_summary = get_chatgpt_summary(URL, reputation, harmless_score, malicious_score)

    c = canvas.Canvas(path, pagesize=A4)
    width, height = A4
    c.setFont("Helvetica", 12)

    text1 = f"This is the threat report for {URL}"
    text2 = f"According to our analysis, {URL} has the following scores:"
    text3 = f"Reputation: {reputation}"
    text4 = f"Harmless rating: {harmless_score}"
    text5 = f"Malicious Score: {malicious_score}"

    text = c.beginText(20 * mm, height - 20 * mm)

    text.textLine(text1)
    text.textLine(text2)
    text.textLine("")
    text.textLine(text3)
    text.textLine(text4)
    text.textLine(text5)
    text.textLine("")
    text.textLine("Executive AI Summary:")
    text.textLine("")

    # 🔹 Step 2: Wrap and Insert AI Summary
    max_width = width - 40 * mm
    wrapped_summary = wrap_text(ai_summary, c, max_width)

    for line in wrapped_summary:
        text.textLine(line)

    c.drawText(text)

    # 🔹 Step 3: Insert Image Below Text
    text_height = text.getY()
    image_x = 20 * mm
    image_y = text_height - 270
    image_height = 250

    c.drawImage(image_path, image_x, image_y, width=233, height=image_height)

    c.save()







if len(sys.argv) < 2:
    exit("Phobos.py requires a URL as an argument to run.\nUsage: phobos.py url")

URL_TO_SCAN = sys.argv[1]                                                   # URL to Scan 
HEADERS = {
    "x-apikey": API_KEY
}



def submit_url(URL_TO_SCAN):
    submit_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(
        submit_url,
        headers=HEADERS,
        data={"url": URL_TO_SCAN}
    )
    response.raise_for_status()
    return response.json()["data"]["id"]

def get_analysis(analysis_id):                                              # Get Analysis ID
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    response = requests.get(analysis_url, headers=HEADERS)
    response.raise_for_status()
    return response.json()

def get_url_details(url_id):
    url_details_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"    # Retrieve details about the URL from Virustotal
    response = requests.get(url_details_url, headers=HEADERS)
    response.raise_for_status()
    return response.json()

def convert_from_epoch(epoch):
    value = datetime.datetime.fromtimestamp(epoch.pop())
    return value.strftime('%Y-%m-%d %H:%M:%S')

def calculate_score(URL, reputation,harmless_score,malicious_score):        # Calulate the scoring
    print("The overall score is based on a range from -100 to +100")
    if reputation is None:                                          # Checks if reputation is None or not defined, and gives a score of 0 
        reputation = 0                                  
    if harmless_score is None:                                      # Checks if harmless score is None or not defined, and gives a score of 0 
        harmless_score = 0
    if malicious_score is None:                                     # Checks if malicious score is None or not defined, and gives a score of 0 
        malicious_score = 0

    if reputation > 50:
        rep_score = 'Good'
    if reputation < 49:
        rep_score = 'Poor'
    if reputation > 0:
        rep_score = 'Bad'
    print(f"The site {URL} has a Reputation Score of {rep_score}")
    print(f"More detailed information can be found in the generated report")
    if harmless_score > 50:
        harm_score = 'Harmless'
        print(f"It's Threat Rating is: {harm_score}")
    if malicious_score > 1:
        harm_score = 'Threatening'
        print(f"The site is potentially malicious with a Malicious Score of: {malicious_score}")

"""
def create_threat_report_pdf(URL, reputation, harmless_score, malicious_score, image_path="reputation.png", path="Threat_report.pdf"):
    c = canvas.Canvas(path, pagesize=A4)
    width, height = A4  # points
    c.setFont("Helvetica", 12)


    text1 = f"This is the threat report for {URL}"
    text2 = f"According to our analysis, {URL}  has the following scores:"
    text3 = f"Reputation: {reputation} "
    text4 = f"Harmless rating: {harmless_score}   "
    text5 = f"Malicious Score: {malicious_score}   "
    text6 = f"These terms may seem confusing and indeed they may sometimes seem contradictory. "
    text7 = f"How can a website have a high reputation score, but also be malicious?"
    text8 = f"A high reputation may indicate a long term, established website, however a malicious" 
    text9 = f"score may indicate a recent infection. Similarly a low reputation may indicate a newly"
    text10 = f"created website. The important component is the harmless indicator"

    text = c.beginText(20 * mm, height - 20 * mm)               # Draw string at x=20mm, y=280mm (roughly top-left on A4)

    text.textLine(text1)
    text.textLine(text2)
    text.textLine("")
    text.textLine(text3)
    text.textLine(text4)
    text.textLine(text5)
    text.textLine("")
    text.textLine(text6)
    text.textLine(text7)
    text.textLine(text8)
    text.textLine(text9)
    text.textLine(text10)

    c.drawText(text)
    text_height = text.getY()                                                       # get current Y position after text
    image_x = 20 * mm
    image_y = text_height - 270
    image_height = 250
    #c.drawImage(image_path, 20 * mm, text_height - 260, width=233, height=250)      #Insert the graph below the last piece of text
    c.drawImage(image_path, image_x, image_y, width=233, height=image_height)

    if reputation > 50:
        rep_score = 'Good'
        text11 = f"The reputation of this site is good, which suggests a well established website"
    if reputation < 49:
        rep_score = 'Poor'
        text11 = f"Reputation of this site is poor, which is not a threat in itself," 
        text12 = f"but should be considered along with other indicators."
    if harmless_score > 50:
        harm_score = 'Harmless'
        text14 = f"The general threat rating of this site is harmless"
    if malicious_score > 20:
        harm_score = "Threatening"
        text14 = f"This site is considered threatening and every precaution should be taken when accessing it."
    elif malicious_score < 19:
        harm_score = "concerning"
        text14 = f"This site's malicous score may be concerning. There have been reports of infectious behaviour"
    elif malicious_score > 2:
        text14 = "Minor infections have been detected for this website. Use care"
    else:
        text14 = "No infections have been reported and this site can be considered Clean"

    text = c.beginText(image_x, image_y - 20)               
    text.textLine(text11)
    text.textLine(text12)
    text.textLine(text14)
    c.drawText(text)
    c.showPage()
    c.save()

"""




def generate_chart(reputation, harmless_score, malicious_score):    # Generate a chart
    #Using Matplotlib to create a plot
    if reputation is None:                                          # Checks if reputation is None or not defined, and gives a score of 0 to avoid breaking the chart
        reputation = 0                                  
    if harmless_score is None:                                      # Checks if harmless score is None or not defined, and gives a score of 0 to avoid breaking the chart
        harmless_score = 0
    if malicious_score is None:                                     # Checks if malicious score is None or not defined, and gives a score of 0 to avoid breaking the chart
        malicious_score = 0

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
    plt.savefig("reputation.png")
    #plt.show()
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

        create_threat_report_pdf(URL, reputation, harmless_score, malicious_score, path="Threat_report.pdf")

        #add_png_image_to_pdf("Threat Report.pdf", "reputation.png")

        print("\n[✓] Analysis complete.")

    except Exception as e:
        print(f"Error during execution: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
