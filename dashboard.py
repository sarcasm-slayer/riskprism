import streamlit as st
import pandas as pd
# Import the logic from your existing api.py file
from api import run_scan, ScanRequest

# --- UI CONFIGURATION ---
st.set_page_config(page_title="RiskPrism", page_icon="🛡️", layout="wide")

st.title("🛡️ RiskPrism: Cyber Risk Dashboard")
st.markdown("Enter a domain below to scan for security, privacy, and compliance risks.")

# --- INPUT SECTION ---
domain_input = st.text_input("Target Domain (e.g., example.com)", "")
scan_button = st.button("Run Security Scan", type="primary")

# --- MAIN LOGIC ---
if scan_button and domain_input:
    with st.spinner(f"Scanning {domain_input}... this may take 10-20 seconds"):
        try:
            # 1. Create the request object required by your api.py
            request_data = ScanRequest(domain=domain_input)
            
            # 2. Call the function directly (No "requests.post" needed!)
            results = run_scan(request_data)
            
            # --- DISPLAY RESULTS ---
            
            # Grade & Score Banner
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Security Grade", results['grade'])
            with col2:
                st.metric("Trust Score", f"{results['score']}/100")
            with col3:
                is_live = "✅ Online" if results['is_live'] else "❌ Offline"
                st.metric("Status", is_live)

            # AI Summary
            st.subheader("📝 Executive Summary")
            st.info(results['ai_summary'])

            # Detailed Findings Table
            st.subheader("🔍 Detailed Findings")
            if results['findings']:
                # Convert list of dicts to a nice dataframe
                df = pd.DataFrame(results['findings'])
                # Select only clean columns if they exist
                cols_to_show = [col for col in ['severity', 'category', 'title', 'description'] if col in df.columns]
                st.dataframe(df[cols_to_show], use_container_width=True)
            else:
                st.success("No major vulnerabilities found!")

            # Compliance Section
            st.subheader("⚖️ Compliance & Governance")
            c_col1, c_col2 = st.columns(2)
            
            with c_col1:
                st.write("**Privacy Checks**")
                privacy = results['compliance']['privacy']
                st.checkbox("Privacy Policy Detected", value=privacy['privacy_policy'], disabled=True)
                st.checkbox("Cookie Banner Detected", value=privacy['cookie_banner'], disabled=True)
            
            with c_col2:
                st.write("**Resilience Checks**")
                resil = results['compliance']['resilience']
                st.write(f"**WAF Detected:** {resil['waf']}")
                st.checkbox("DNSSEC Enabled", value=resil['dnssec'], disabled=True)

        except Exception as e:
            st.error(f"An error occurred during the scan: {e}")