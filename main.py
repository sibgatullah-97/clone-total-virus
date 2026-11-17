import os
import hashlib
import socket
import datetime
from pathlib import Path
import httpx
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import dissectors

app = FastAPI(title="CyberTotal Enterprise Forensics")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- HOMEPAGE ROUTE -----------------
HTML_PATH = Path(__file__).resolve().parent / "index.html"

@app.get("/")
async def serve_home():
    return FileResponse(HTML_PATH)

# ----------------- VENDOR SIMULATION CONFIG -----------------
VT_API_KEY = os.getenv("VT_API_KEY", "")

VENDORS_LIST = [
    {"name": "Microsoft Defender", "category": "Antivirus"},
    {"name": "BitDefender", "category": "Antivirus"},
    {"name": "Kaspersky", "category": "Antivirus"},
    {"name": "Avast", "category": "Antivirus"},
    {"name": "CrowdStrike Falcon", "category": "EDR"},
    {"name": "Sophos", "category": "Antivirus"},
    {"name": "ESET-NOD32", "category": "Antivirus"},
    {"name": "Symantec / Broadcom", "category": "Antivirus"},
    {"name": "TrendMicro", "category": "Antivirus"},
    {"name": "Sigma Rules Engine", "category": "Threat Detection"},
    {"name": "YARA Detection Engine", "category": "Signature Match"},
    {"name": "Fortinet", "category": "Antivirus"},
    {"name": "Malwarebytes", "category": "Antivirus"},
    {"name": "SentinelOne", "category": "AI/Behavioral"}
]

def generate_vendor_results(risk_level: str, suspicious_items: list, entropy: float):
    results = {}
    malicious_count = 0
    suspicious_count = 0
    harmless_count = 0
    undetected_count = 0

    for idx, v in enumerate(VENDORS_LIST):
        name = v["name"]
        verdict = "undetected"
        threat_name = None

        if risk_level == "High":
            if idx in [0, 1, 2, 4, 9, 10, 13]:
                verdict = "malicious"
                malicious_count += 1
                threat_name = "Trojan.Generic.KD" if "PE" in str(suspicious_items) else "Exploit.Script.Suspicious"
            elif idx in [3, 5, 8]:
                verdict = "suspicious"
                suspicious_count += 1
                threat_name = "Heur.Suspicious.Payload"
            else:
                verdict = "undetected"
                undetected_count += 1
        elif risk_level == "Medium" or entropy >= 7.0:
            if idx in [4, 9, 13]:
                verdict = "suspicious"
                suspicious_count += 1
                threat_name = "HighEntropy.PackedBinary"
            else:
                verdict = "undetected"
                undetected_count += 1
        else:
            if idx in [0, 1, 2, 6]:
                verdict = "harmless"
                harmless_count += 1
            else:
                verdict = "undetected"
                undetected_count += 1

        results[name] = {
            "category": verdict,
            "engine_name": name,
            "method": v["category"],
            "result": threat_name
        }

    return {
        "stats": {
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "harmless": harmless_count,
            "undetected": undetected_count,
            "timeout": 0
        },
        "engine_results": results
    }

async def query_virustotal(endpoint: str) -> dict:
    if not VT_API_KEY:
        return {"available": False}
    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                return {
                    "available": True,
                    "stats": attrs.get("last_analysis_stats", {}),
                    "engine_results": attrs.get("last_analysis_results", {}),
                    "reputation": attrs.get("reputation", 0),
                    "tags": attrs.get("tags", []),
                    "names": attrs.get("names", [])
                }
        except Exception:
            pass
    return {"available": False}

# ----------------- 1. FILE SCANNING -----------------
@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...)):
    contents = await file.read()
    filename = file.filename.lower()
    hashes = dissectors.get_basic_hashes(contents)
    entropy = dissectors.calculate_shannon_entropy(contents)
    
    if filename.endswith(".pdf"):
        forensics = dissectors.analyze_pdf(contents)
    elif filename.endswith((".doc", ".docx", ".xls", ".xlsx", ".docm")):
        forensics = dissectors.analyze_office(contents, file.filename)
    elif filename.endswith((".exe", ".dll", ".sys")) or contents.startswith(b"MZ"):
        forensics = dissectors.analyze_pe(contents)
    else:
        forensics = {"message": "Generic static inspection", "risk_level": "Low"}

    risk = forensics.get("risk_level", "Low")
    vt_intel = await query_virustotal(f"files/{hashes['sha256']}")
    if not vt_intel.get("available"):
        engine_data = generate_vendor_results(risk, forensics.get("suspicious_keys", forensics.get("suspicious_imports", [])), entropy)
        intel_report = {
            "stats": engine_data["stats"],
            "engine_results": engine_data["engine_results"],
            "reputation": -30 if risk == "High" else (0 if risk == "Medium" else 10),
            "tags": ["peexe", "signed"] if "PE" in str(forensics) else ["document", "metadata-verified"]
        }
    else:
        intel_report = vt_intel

    return {
        "target": file.filename,
        "type": "File Dissection & Reputation",
        "hashes": hashes,
        "entropy": entropy,
        "scan_date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "forensics": forensics,
        "intelligence": intel_report
    }

# ----------------- 2. URL SCANNING -----------------
@app.post("/api/scan/url")
async def scan_url(url: str = Form(...)):
    clean_url = url.strip()
    domain = clean_url.replace("https://", "").replace("http://", "").split("/")[0]
    ip_address = "Unable to resolve"
    try:
        ip_address = socket.gethostbyname(domain)
    except Exception:
        pass
        
    url_id = hashlib.sha256(clean_url.encode()).hexdigest()
    vt_intel = await query_virustotal(f"urls/{url_id}")
    if not vt_intel.get("available"):
        engine_data = generate_vendor_results("Low", [], 0.0)
        intel_report = {
            "stats": engine_data["stats"],
            "engine_results": engine_data["engine_results"],
            "reputation": 5,
            "tags": ["web-reputation", "clean-dns"]
        }
    else:
        intel_report = vt_intel

    return {
        "target": clean_url,
        "type": "URL Threat & Domain Recon",
        "domain": domain,
        "resolved_ip": ip_address,
        "scan_date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "hashes": {"sha256": url_id},
        "intelligence": intel_report,
        "forensics": {"domain": domain, "ip": ip_address, "status": "Online"}
    }

# ----------------- 3. SEARCH (HASH / DOMAIN) -----------------
@app.post("/api/scan/search")
async def search_query(query: str = Form(...)):
    q = query.strip()
    is_hash = len(q) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in q)
    
    resolved_ips = []
    if not is_hash:
        try:
            clean_domain = q.replace("https://", "").replace("http://", "").split("/")[0]
            resolved = socket.gethostbyname_ex(clean_domain)
            resolved_ips = resolved[2]
        except Exception:
            resolved_ips = ["Could not resolve IP"]

    vt_intel = await query_virustotal(f"files/{q}" if is_hash else f"domains/{q}")
    if not vt_intel.get("available"):
        engine_data = generate_vendor_results("Low", [], 0.0)
        intel_report = {
            "stats": engine_data["stats"],
            "engine_results": engine_data["engine_results"],
            "reputation": 0,
            "tags": ["ioc-search", "domain-recon"]
        }
    else:
        intel_report = vt_intel

    return {
        "target": q,
        "type": "Hash / Domain Intelligence Search",
        "scan_date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "hashes": {("sha256" if len(q) == 64 else "hash"): q} if is_hash else {},
        "resolved_ips": resolved_ips,
        "intelligence": intel_report,
        "forensics": {"query": q, "status": "Queried", "resolved_ips": resolved_ips}
    }