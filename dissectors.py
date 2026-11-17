import math
import hashlib
import io
from pypdf import PdfReader
from oletools.olevba import VBA_Parser
import pefile

def get_basic_hashes(data: bytes) -> dict:
    return {
        "filesize": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 3)

def analyze_pdf(data: bytes) -> dict:
    report = {"metadata": {}, "pages": 0, "suspicious_keys": [], "risk_level": "Low"}
    try:
        reader = PdfReader(io.BytesIO(data))
        report["pages"] = len(reader.pages)
        if reader.metadata:
            report["metadata"] = {k.strip("/"): str(v) for k, v in reader.metadata.items() if v}
        
        raw_text = data.decode("latin-1", errors="ignore")
        risky_triggers = [
            ("/JavaScript", "Embedded JavaScript code"),
            ("/JS", "Abbreviated JavaScript tag"),
            ("/Launch", "Application launch action"),
            ("/OpenAction", "Auto-run on file open"),
            ("/EmbeddedFiles", "Attached embedded binary files"),
            ("/URI", "Outbound web link")
        ]
        for tag, desc in risky_triggers:
            count = raw_text.count(tag)
            if count > 0:
                report["suspicious_keys"].append({"tag": tag, "count": count, "description": desc})
        
        if any(item["tag"] in ["/JavaScript", "/JS", "/Launch"] for item in report["suspicious_keys"]):
            report["risk_level"] = "High"
        elif report["suspicious_keys"]:
            report["risk_level"] = "Medium"
    except Exception as e:
        report["error"] = str(e)
    return report

def analyze_office(data: bytes, filename: str) -> dict:
    report = {"has_macros": False, "suspicious_keywords": [], "risk_level": "Low"}
    try:
        vba_parser = VBA_Parser(filename=filename, data=data)
        if vba_parser.detect_vba_macros():
            report["has_macros"] = True
            report["risk_level"] = "High"
            for kw_type, keyword, desc in vba_parser.analyze_macros():
                report["suspicious_keywords"].append({"type": kw_type, "keyword": keyword, "description": desc})
        vba_parser.close()
    except Exception as e:
        report["error"] = str(e)
    return report

def analyze_pe(data: bytes) -> dict:
    report = {
        "machine_type": "Unknown",
        "compile_time": "Unknown",
        "sections": [],
        "suspicious_imports": [],
        "overall_entropy": calculate_shannon_entropy(data),
        "risk_level": "Low"
    }
    try:
        pe = pefile.PE(data=data)
        report["machine_type"] = hex(pe.FILE_HEADER.Machine)
        report["compile_time"] = pe.FILE_HEADER.dump_dict().get("TimeDateStamp", {}).get("Value", "Unknown")
        
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            entropy = section.get_entropy()
            report["sections"].append({
                "name": sec_name,
                "entropy": round(entropy, 3),
                "is_packed_suspect": entropy >= 7.2
            })
        
        suspicious_apis = {
            "VirtualAlloc": "Memory injection",
            "WriteProcessMemory": "Process tampering",
            "CreateRemoteThread": "Thread hijacking",
            "URLDownloadToFileA": "Dropper payload",
            "WinExec": "Command execution"
        }
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode('utf-8', errors='ignore')
                        if name in suspicious_apis:
                            report["suspicious_imports"].append({
                                "api": name,
                                "dll": entry.dll.decode('utf-8', errors='ignore'),
                                "description": suspicious_apis[name]
                            })
        
        if report["suspicious_imports"] or any(s["is_packed_suspect"] for s in report["sections"]):
            report["risk_level"] = "High" if len(report["suspicious_imports"]) > 1 else "Medium"
    except Exception as e:
        report["error"] = str(e)
    return report