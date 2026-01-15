import subprocess
import sys
from nvdlib import searchCVE
import streamlit as st
import datetime
from dotenv import load_dotenv 
import time

# used AI to generate a more comprehensive keyword list to use it for the filter to help the company reduce the costs ;)
KEYWORDS = [
    # --- General Terms ---
    "SCADA", "ICS", "Industrial Control", "HMI", "PLC", "RTU", "DCS",
    "SIS", "Process Control", "Operational Technology",

    # --- Protocols (The languages machines speak) ---
    "Modbus", "DNP3", "Profinet", "Profibus", "EtherNet/IP", "BACnet",
    "OPC UA", "IEC 61850", "EtherCAT", "CIP", "MMS",

    # --- Major Vendors (The big players) ---
    "Siemens", "Rockwell", "Schneider", "ABB", "Honeywell",
    "Emerson", "Mitsubishi", "Omron", "Yokogawa", "General Electric", "Fanuc",

    # --- Specific Product Lines (High probability of being OT) ---
    "Simatic", "WinCC", "Tia Portal",  # Siemens
    "Logix", "FactoryTalk", "Rslinx",  # Rockwell/Allen-Bradley
    "DeltaV", "Ovation",               # Emerson
    "Triconex", "Foxboro",             # Schneider
    "Centum", "ProSafe",               # Yokogawa
    "Wonderware", "Citect"             # AVEVA/Schneider
]

# Function to detect potential threats
# this also filters out unrelated threats before sending to LLM to check


def is_potential_ot(description):
  if not description:
    return False
  return any(keyword.lower() in description.lower() for keyword in KEYWORDS)

# using Gemini to analyze the descriptions of the CVEs

import json
import os
import google.generativeai as genai

load_dotenv()
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)

model = genai.GenerativeModel(
        model_name='gemini-2.5-flash-lite',
        generation_config={'response_mime_type':'application/json'} # set the output format
    )

def analyze_with_gemini(description):
    short_desc = description[:800] 
    
    prompt=f"""
    You are an expert OT threat analyst with 160 IQ.
    Thoroughly analyze the following CVE description.
    Return ONLY a JSON object with exactly these keys:
    1. "ot_related" : boolean (True if OT/ICS/SCADA related, False otherwise).
    2. "reason" : string (an expert-level, detailed explanation of why. If "ot_related" is True, explain why this vulnerability is dangerous).

    ---------------------
    Description:
    ---------------------
    {short_desc}
    """

    attempts = 0
    while attempts < 3:
        try:
            response = model.generate_content(prompt)
            return json.loads(response.text)
        except Exception as e:
            if "429" in str(e):
                wait_time = (attempts + 1) * 20 # 20s, then 40s, then 60s
                print(f"Quota hit. Backing off for {wait_time}s...")
                time.sleep(wait_time)
                attempts += 1
            else:
                print(f"AI error: {e}")
                return {"ot_related": False, "reason": "Error"}

    try:
        response = model.generate_content(prompt)
        return json.loads(response.text) #used this to convert from JSON object to python dict

    except Exception as e:
        print(f"AI error: {e}")
        return {"ot_related":False, "reason":"Error processing request"} # safe output
    

# Main Program
if __name__== "__main__":
  seen_cves = set()
  approved_cves=dict()
  dashboard_data=dict()
  NVD_API = os.environ.get('NVD_API_KEY')
  while True:
    end = datetime.datetime.now()
    start = end - datetime.timedelta(days=1)
    r = searchCVE(pubStartDate=start, pubEndDate=end, key=NVD_API)
    print(f"Fetched {len(r)} records.")

    for cve in r[:5]: # Print first 5 to check
        print(f"{cve.id}: {cve.descriptions[0].value}")
    for cve in r:
      if cve.id not in seen_cves and cve.vulnStatus != "Rejected": #check if this is a new cve and wasn't rejected as a vulnerability
        seen_cves.add(cve.id) #to avoid reprocessing the same cve

        try:
          description = cve.descriptions[0].value #to get the description
          if is_potential_ot(description):  # check if the CVE can be OT related
              print(f"New potential threat is detected: {cve.id}")
              print(f"sending {cve.id} description to LLM for analysis...")
              response = analyze_with_gemini(description)
              time.sleep(5) # making sure to wait 20 seconds between each check to prevent hitting the API limit
              
              if response['ot_related'] == True: # check if the response is OT related to keep/ignore it
                print(f"""
                ###################################
                APPROVED: {cve.id} is an OT threat!
                ###################################
                """)

                try:
                  cvss = cve.metrics.cvssMetricV31[0].cvssData.baseScore #new CVEs might not have a severity score. Implemented a safety check
                  severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity
                except:
                  cvss = 'N/A' # if no severity score. set the severity value to 'N/A'
                  severity = 'N/A'
                #initialized this to save every new approved CVE
                approved_cves[cve.id] = {'cvss':cvss,
                                        'severity':severity,
                                        'description':f"{description}",
                                        'ai_insight':f'{response['reason']}'}
                new_entry = {'cve_id':f'{cve.id}'}|approved_cves[cve.id] #concatenating the dict to output a separate new output to pass to the dashboard
                
                # output the OT threat found to a JSON file
                try:
                  with open('output_sample.json',mode='r') as f: #used mode=a to append to existing file and not overwrite existing data
                    data = json.load(f)
                    
                    # checking and correcting the data type
                    if isinstance(data,dict):
                      data = [data]
                    elif not isinstance(data,list):
                      data = []

                except:
                  data = []
                
                data.append(new_entry)

                if data:
                  with open('output_sample.json',mode='w') as f:
                    json.dump(data,f,indent=4)
          else:
            continue

        except:
          continue
    time.sleep(600)
