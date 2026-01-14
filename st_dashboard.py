import json
import os 
import streamlit as st
import pandas as pd

st.set_page_config(page_title='OT Threat Guard',layout='wide') #to set the tab title and wide layout

import streamlit as st
import base64

# Function to convert local image to data-uri
def get_base64_of_bin_file(bin_file):
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()

# 1. Prepare your image and target URL
logo_path = 'logo-header-dark.png'
logo_base64 = get_base64_of_bin_file(logo_path)
target_url = "https://control-point.io/" # Change this to your desired link

# 2. Display centered, clickable logo
st.markdown(
    f"""
    <div style="text-align: center;">
        <a href="{target_url}" target="_blank" style="text-decoration: none;">
            <img src="data:image/png;base64,{logo_base64}" 
                 style="width: 300px; margin-bottom: 20px; cursor: pointer;">
        </a>
    </div>
    """,
    unsafe_allow_html=True
)

#=========================#

st.markdown("<span style='color: #CF0000;font-size:60px; font-weight:bold;'>"
                "ControlPoint - OT Threat Intelligence Agent"
                "</span>",
                unsafe_allow_html=True
                )
st.markdown('## Watching for industrial cyber threats in real-time...')
st.divider()


def load_data():
    file_path = 'output_sample.json'
    if not os.path.exists(file_path):
        return [] # if file doesn't exist return empty list
    
    try:
        with open(file_path,'r') as f:
            return json.load(f)
    except:
        st.markdown("The agent hasn't found any threats yet")
        return [] #return empty if the file is corrupted
    
data = load_data()

st.markdown("<span style='color: #CF0000;font-size:30px; font-weight:bold;'>"
                "Number of OT threats found:"
                "</span>",
                unsafe_allow_html=True
                ) 
with st.container(border=True): # container around the metric to make it better looking
    st.metric("Total OT Threats",len(data))

if data:
    st.dataframe(pd.DataFrame(data).iloc[:,:3])

    st.markdown("<span style='color: #CF0000;font-size:30px; font-weight:bold;'>"
                "Click on the CVE ID to see its details"
                "</span>",
                unsafe_allow_html=True
                ) 
    for item in data:
        # created an expander that shows the AI insights for every CVE
        with st.expander(f"ID: {item['cve_id']} - Severity: {item['severity']}\n"):
            st.write(f"### **AI Insight:**\n {item['ai_insight']}")
            st.info(f"### **Full Description:**\n {item['description']}")

if st.button('Refresh'):
    st.rerun()

# st.logo(image='logo-header-dark.png',size='large',link='https://control-point.io/')