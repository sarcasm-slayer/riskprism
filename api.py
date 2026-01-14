from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import ssl
import socket
import whois
import dns.resolver
from datetime import datetime
from bs4 import BeautifulSoup

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    domain: str

# --- GRC MAPPING ---
GRC_MAPPING = {
    "Missing HSTS": {"category": "App Sec", "iso": "A.14.1.2", "nist": "PR.DS-2", "mitre": "T1595"},
    "Missing Clickjack": {"category": "App Sec", "iso": "A.14.1.3", "nist": "PR.IP-1", "mitre": "T1189"},
    "Server Version": {"category": "App Sec", "iso": "A.12.6.1", "nist": "PR.IP-12", "mitre": "T1592"},
    "SSL Expired": {"category": "Encryption", "iso": "A.10.1.1", "nist": "PR.DS-1", "mitre": "T1589"},
    "SSL Handshake Failed": {"category": "Encryption", "iso": "A.10.1.1", "nist": "PR.DS-1", "mitre": "T1589"},
    "Obsolete TLS": {"category": "Encryption", "iso": "A.10.1.1", "nist": "PR.DS-2", "mitre": "T1040"},
    "Open Port": {"category": "Network Sec", "iso": "A.13.1.1", "nist": "PR.AC-3", "mitre": "T1190"},
    "Shadow IT": {"category": "Network Sec", "iso": "A.8.1.1", "nist": "ID.AM-1", "mitre": "T1583"},
    "Missing DMARC": {"category": "Brand Protection", "iso": "A.13.2.1", "nist": "PR.DS-5", "mitre": "T1566"},
    "Missing SPF": {"category": "Brand Protection", "iso": "A.13.2.1", "nist": "PR.DS-5", "mitre": "T1566"},
    "Missing Privacy Policy": {"category": "Data Privacy", "iso": "A.18.1.4", "nist": "ID.GV-3", "mitre": "-"},
    "Missing Cookie Banner": {"category": "Data Privacy", "iso": "A.18.1.4", "nist": "ID.GV-3", "mitre": "-"},
    "Missing Security.txt": {"category": "Corp Governance", "iso": "A.12.6.1", "nist": "ID.RA-1", "mitre": "-"},
    "No WAF Detected": {"category": "Resilience", "iso": "A.13.1", "nist": "PR.PT-4", "mitre": "T1498"},
    "Missing DNSSEC": {"category": "Resilience", "iso": "A.10.1.2", "nist": "PR.DS-5", "mitre": "T1098"}
}

def enrich_finding(finding):
    finding["compliance"] = {"iso": "-", "nist": "-", "mitre": "-"}
    finding["category"] = "General"
    for key, info in GRC_MAPPING.items():
        if key.lower() in finding["title"].lower():
            finding["compliance"] = info
            finding["category"] = info["category"]
            break
    return finding

# --- LOGIC ENGINE ---
def generate_smart_summary(grade, score, findings, compliance_scores, is_live):
    if not is_live:
        return f"CRITICAL: The asset is unreachable or does not exist. Security posture cannot be verified. This represents a total loss of availability (Score: {score}/100)."

    if grade == "A":
        opening = f"Security posture is robust (Score: {score}/100)."
    elif grade == "B":
        opening = f"Security posture is healthy (Score: {score}/100) with minor gaps."
    elif grade == "C":
        opening = f"Elevated risk detected (Score: {score}/100)."
    else:
        opening = f"CRITICAL RISK (Score: {score}/100). Immediate action required."

    criticals = [f for f in findings if f['severity'] in ['Critical', 'High']]
    if criticals:
        issue_text = f"Identified {len(criticals)} critical issues in {criticals[0]['category']}."
    elif len(findings) > 0:
        issue_text = f"Found {len(findings)} moderate configuration issues."
    else:
        issue_text = "No major external vulnerabilities found."

    lowest = min(compliance_scores, key=lambda k: compliance_scores[k]['score'])
    low_val = compliance_scores[lowest]['score']
    
    if low_val < 60:
        comp_text = f"However, {lowest.upper()} compliance is lagging ({low_val}%) due to missing governance controls."
    else:
        comp_text = "Compliance maturity aligns with industry standards."

    return f"{opening} {issue_text} {comp_text}"

# --- AGENTS ---
def check_privacy_compliance(url, is_live):
    if not is_live: return 0, [], {"privacy_policy": False, "cookie_banner": False, "trust_badges": []}
    findings = []
    deduction = 0
    signals = {"privacy_policy": False, "cookie_banner": False, "trust_badges": []}
    try:
        res = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(res.text, 'html.parser')
        text = soup.get_text().lower()
        
        keywords = ["privacy policy", "privacy notice", "data policy", "data protection"]
        found = False
        if soup.find('a', string=lambda t: t and any(k in t.lower() for k in keywords)): found = True
        elif any(k in text[-3000:] for k in keywords): found = True
            
        if found: signals["privacy_policy"] = True
        else:
            findings.append(enrich_finding({"title": "Missing Privacy Policy", "severity": "Medium", "description": "No Privacy/Data Policy link found."}))
            deduction += 20 

        if any(k in str(soup).lower() for k in ["cookie", "consent", "onetrust"]): signals["cookie_banner"] = True
        for img in soup.find_all('img'):
            if "soc" in img.get('alt','').lower(): signals["trust_badges"].append("SOC 2")
    except: pass
    return deduction, findings, signals

def check_resilience(domain, is_live):
    if not is_live: return 0, [], {"waf": "None", "dnssec": False}
    findings = []
    deduction = 0
    signals = {"waf": "None", "dnssec": False}
    try:
        r = requests.head(f"https://{domain}", timeout=3)
        wafs = {"cloudflare": "Cloudflare", "x-amz-cf-id": "AWS", "akamai": "Akamai"}
        for k,v in wafs.items():
            if k in str(r.headers).lower(): signals["waf"] = v
        if signals["waf"] == "None":
            findings.append(enrich_finding({"title": "No WAF Detected", "severity": "Low", "description": "No WAF headers."}))
        
        if len(dns.resolver.resolve(domain, 'DNSKEY')) > 0: signals["dnssec"] = True
    except:
        findings.append(enrich_finding({"title": "Missing DNSSEC", "severity": "Low", "description": "Domain unsigned."}))
        deduction += 5
    return deduction, findings, signals

# --- STANDARD AGENTS (Condensed) ---
def check_security_txt(d, is_live):
    if not is_live: return 0, [], False
    try: return 0, [], requests.get(f"https://{d}/.well-known/security.txt", timeout=2).status_code == 200
    except: return 0, [], False

def check_whois(d):
    i = {"registrar": "Unknown", "country": "Unknown", "age": 0}
    try:
        w = whois.whois(d)
        i["registrar"] = w.registrar[0] if isinstance(w.registrar, list) else w.registrar or "Unknown"
        i["country"] = w.country or "Global"
        if w.creation_date: i["age"] = datetime.now().year - (w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date).year
    except: pass
    return 0, [], i

def check_ssl_security(d):
    f, ded, tls = [], 0, "Unknown"
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((d, 443), timeout=3) as s:
            with ctx.wrap_socket(s, server_hostname=d) as ss:
                if (datetime.strptime(ss.getpeercert()['notAfter'], "%b %d %H:%M:%S %Y %Z") - datetime.now()).days < 0:
                    f.append(enrich_finding({"title": "SSL Expired", "severity": "Critical", "description": "Expired."})); ded += 50
                tls = ss.version()
                if tls in ["TLSv1.1", "TLSv1.0"]:
                    f.append(enrich_finding({"title": "Obsolete TLS", "severity": "High", "description": "Old TLS."})); ded += 20
    except: f.append(enrich_finding({"title": "SSL Handshake Failed", "severity": "High", "description": "Failed."})); ded += 50
    return ded, f, tls

def check_email_security(d):
    f, ded, r = [], 0, {"dmarc": "Missing"}
    try:
        for t in dns.resolver.resolve(f"_dmarc.{d}", 'TXT'): 
            if "v=DMARC1" in str(t): r["dmarc"] = str(t).replace('"','')
    except: f.append(enrich_finding({"title": "Missing DMARC", "severity": "High", "description": "Missing."})); ded += 25
    return ded, f, r

def check_security_headers(url, is_live):
    if not is_live: return 0, []
    f, ded = [], 0
    try:
        r = requests.get(url, timeout=3)
        if 'Strict-Transport-Security' not in r.headers: f.append(enrich_finding({"title": "Missing HSTS", "severity": "Medium", "description": "No HSTS."})); ded += 10
    except: pass
    return ded, f

def check_tech_stack(url, is_live):
    if not is_live: return 0, [], []
    f, ded, t = [], 0, []
    try:
        r = requests.get(url, timeout=3)
        s = r.headers.get('Server', 'Unknown')
        if s != 'Unknown': t.append({"name": s.split('/')[0], "type": "Web Server"})
    except: pass
    return ded, f, t

def find_subdomains(d):
    s = []
    try:
        r = requests.get(f"https://crt.sh/?q=%.{d}&output=json", timeout=5)
        if r.status_code == 200:
            for e in r.json()[:10]:
                n = e['name_value'].split('\n')[0].replace('*.', '')
                if d in n and n not in s: s.append(n)
    except: pass
    return s, []

# --- CALCULATORS ---
def calculate_scores(findings, privacy, resilience, sec_txt, tls):
    tech_ded = sum([{"Critical": 40, "High": 25, "Medium": 15, "Low": 5}.get(f["severity"], 0) for f in findings])
    base = max(0, 100 - tech_ded)
    p = 1 if privacy["privacy_policy"] else 0
    w = 1 if resilience["waf"] != "None" else 0
    return {"iso": {"score": int((base * 0.7) + (w * 30))}, "nist": {"score": int((base * 0.6) + (w * 40))}, "gdpr": {"score": int((base * 0.2) + (p * 80))}}

def calculate_category_grades(findings, is_live):
    # Updated Categories
    scores = {"Network Sec": 100, "App Sec": 100, "Encryption": 100, "Data Privacy": 100, "Corp Governance": 100, "Resilience": 100, "Brand Protection": 100}
    
    # THE NUCLEAR FIX: If dead, EVERYTHING is N/A
    if not is_live:
        for k in scores.keys(): scores[k] = "N/A"
    
    for f in findings:
        cat = f.get("category", "General")
        if cat in scores and scores[cat] != "N/A":
            ded = {"Critical": 40, "High": 25, "Medium": 15, "Low": 5}.get(f["severity"], 0)
            scores[cat] = max(0, scores[cat] - ded)
            
    grades = {}
    for k, v in scores.items():
        if v == "N/A": grades[k] = "N/A"
        else: grades[k] = "A" if v >= 90 else "B" if v >= 80 else "C" if v >= 70 else "D" if v >= 60 else "F"
    return grades

@app.post("/scan")
def run_scan(request: ScanRequest):
    d = request.domain.replace("https://", "").replace("http://", "").split("/")[0]
    url = f"https://{d}"
    
    is_live = False
    try:
        requests.get(url, timeout=3)
        is_live = True
    except: is_live = False

    h_ded, h_find = check_security_headers(url, is_live)
    s_ded, s_find, tls = check_ssl_security(d)
    w_ded, w_find, ident = check_whois(d)
    e_ded, e_find, email = check_email_security(d)
    subs, sub_find = find_subdomains(d)
    st_ded, st_find, sec_txt = check_security_txt(d, is_live)
    t_ded, t_find, tech = check_tech_stack(url, is_live)
    p_ded, p_find, privacy = check_privacy_compliance(url, is_live)
    r_ded, r_find, resil = check_resilience(d, is_live)

    all_findings = h_find + s_find + e_find + sub_find + st_find + p_find + r_find + t_find
    
    # If not live, wipe findings that might be misleading, keep only "Unreachable"
    if not is_live:
        all_findings = [enrich_finding({"title": "Asset Unreachable", "severity": "Critical", "category": "Resilience", "description": "Server offline."})]
        final_score = 0
        grade = "F"
    else:
        total_deduction = sum([{"Critical": 40, "High": 25, "Medium": 15, "Low": 5}.get(f["severity"], 0) for f in all_findings])
        final_score = max(0, 100 - total_deduction)
        grade = "A" if final_score >= 90 else "B" if final_score >= 80 else "C" if final_score >= 70 else "D" if final_score >= 60 else "F"

    comp_scores = calculate_scores(all_findings, privacy, resil, sec_txt, tls)
    summary = generate_smart_summary(grade, final_score, all_findings, comp_scores, is_live)

    return {
        "domain": d, "is_live": is_live, "grade": grade, "score": final_score, "findings": all_findings,
        "identity": ident, "security_txt": sec_txt, "tls_version": tls, "email_security": email,
        "subdomains": subs, "technologies": tech, "compliance": { "privacy": privacy, "resilience": resil },
        "category_grades": calculate_category_grades(all_findings, is_live),
        "ai_summary": summary,
        # Generate breakdown only if there are findings
        "breakdown": [{"reason": f['title'], "points": {"Critical":40,"High":25,"Medium":15,"Low":5}.get(f['severity'],0)} for f in all_findings]
    }

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)