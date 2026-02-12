"""
beta-AIO - Universal Data Analysis
Recursive analysis across all data types
"""
import streamlit as st
import json
import re
from datetime import datetime
from typing import Dict, List, Any, Set, Tuple

import config
from constants import COUNTRY_NAMES, COUNTRY_TLDS
from sources import IP_SOURCES, HASH_SOURCES, URL_SOURCES, DOMAIN_SOURCES, EMAIL_SOURCES


# Country codes and TLDs imported from constants.py


def normalize_country(country_input: str) -> str:
    """Normalize country code/name to standard format: CODE, Full Name"""
    if not country_input:
        return None
    
    country = country_input.strip().upper()
    
    # If it's a code
    if len(country) == 2 and country in COUNTRY_NAMES:
        return f"{country}, {COUNTRY_NAMES[country]}"
    
    # If it's already a name, find the code
    for code, name in COUNTRY_NAMES.items():
        if name.upper() == country or name.upper() in country:
            return f"{code}, {name}"
    
    # Return as-is with original casing
    return country_input


# Page config
st.set_page_config(
    page_title="beta-AIO",
    page_icon="O",
    layout="wide"
)

# CSS
st.markdown("""
<style>
    .stApp { background-color: #0e1117; color: #fafafa; }
    .main-header { color: #fafafa; font-size: 2.5rem; font-weight: 600; text-align: center; margin-bottom: 1rem; border-bottom: 1px solid #333; padding-bottom: 1rem; }
    .attribution { color: #888; font-size: 0.85rem; }
</style>
""", unsafe_allow_html=True)


def get_api_keys():
    """Get API keys from config"""
    return {
        "VirusTotal": config.VIRUSTOTAL_API_KEY,
        "VirusTotalIP": config.VIRUSTOTAL_API_KEY,
        "VirusTotalHash": config.VIRUSTOTAL_API_KEY,
        "VirusTotalURL": config.VIRUSTOTAL_API_KEY,
        "VirusTotalDomain": config.VIRUSTOTAL_API_KEY,
        "AbuseIPDB": config.ABUSEIPDB_API_KEY,
        "OTXHash": config.OTX_API_KEY,
        "OTXURL": config.OTX_API_KEY,
        "OTX_AlienVault": config.OTX_API_KEY,
        "AlienVault_OTX": config.OTX_API_KEY,
        "AlienVaultOTX": config.OTX_API_KEY,
        "AlienVaultDomain": config.OTX_API_KEY,
        "URLScan": config.URLSCAN_API_KEY,
        "URLhaus": config.ABUSECH_API_KEY,
        "MalwareBazaar": config.ABUSECH_API_KEY,
        "ThreatFoxHash": config.ABUSECH_API_KEY,
        "ThreatFox": config.ABUSECH_API_KEY,
        "HybridAnalysis": config.HYBRIDANALYSIS_API_KEY,
        "GoogleSB": config.GOOGLE_SAFEBROWSING_API_KEY,
        "IPQS": config.IPQS_API_KEY,
        "Hunter": config.HUNTER_API_KEY,
        "HIBP": config.HIBP_API_KEY,
        "Dehashed": config.DEHASHED_API_KEY,
        "LeakCheck": config.LEAKCHECK_API_KEY,
    }


def refang(data: str) -> str:
    """Convert defanged data to real format"""
    result = data.strip()
    # Handle double brackets first (must come before single brackets)
    result = re.sub(r'\[\[\.]]', '.', result)  # [[.]] -> .
    result = re.sub(r'\[\[\.\]\]', '.', result)  # [[.]] with escaped brackets
    result = re.sub(r'\[\.+\]', '.', result)  # [.] or [..] -> .
    result = re.sub(r'\[:\]', ':', result)  # [:] -> :
    result = re.sub(r'\[\@\]', '@', result)  # [@] -> @
    result = re.sub(r'hxxp', 'http', result, flags=re.IGNORECASE)  # hxxp -> http
    result = re.sub(r'hXXp', 'http', result)  # hXXp -> http
    result = re.sub(r'\(dot\)', '.', result, flags=re.IGNORECASE)  # (dot) -> .
    result = re.sub(r'\{dot\}', '.', result, flags=re.IGNORECASE)  # {dot} -> .
    return result


def classify_data(data: str) -> str:
    """Classify data type"""
    if re.match(r'^[a-fA-F0-9]{32}$', data):
        return "hash"
    if re.match(r'^[a-fA-F0-9]{40}$', data):
        return "hash"
    if re.match(r'^[a-fA-F0-9]{64}$', data):
        return "hash"
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', data):
        return "ip"
    if data.startswith("http://") or data.startswith("https://"):
        return "url"
    if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', data):
        return "email"
    if '.' in data and '/' not in data:
        return "domain"
    if '/' in data:
        return "url"
    return "unknown"


def format_value(value):
    """Format a value for display"""
    if value is None or value == "" or value == []:
        return None
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        if len(value) == 0:
            return None
        return ", ".join(str(v) for v in value[:10])
    if isinstance(value, dict):
        return json.dumps(value, indent=2)
    return str(value)


def extract_main_domain(domain: str) -> str:
    """Extract main domain from subdomain (e.g., mail.github.com → github.com)"""
    domain = domain.lower().strip(".")
    parts = domain.split(".")
    
    if len(parts) <= 2:
        return domain  # Already main domain (e.g., github.com)
    
    # Use comprehensive country TLDs from constants
    # (includes .co.uk, .com.au, .co.in, etc.)
    
    last_two = ".".join(parts[-2:])
    if last_two in COUNTRY_TLDS:
        return ".".join(parts[-3:])  # e.g., example.co.uk
    
    return ".".join(parts[-2:])  # e.g., github.com


def extract_related_data(results: Dict[str, Dict]) -> Dict[str, List[Dict]]:
    """Universal data extraction - works for IP, Hash, URL, Domain results"""
    related = {"domains": [], "ips": [], "hashes": [], "urls": [], "files": []}
    
    for source_name, result in results.items():
        details = result.get("details", {})
        
        # === DOMAINS ===
        domain_keys = [
            "hostnames", "domain", "ptr_record", "passive_dns_domains", "subdomains",
            "domains", "compromised_hosts", "contacted_domains", "hostname",
            "page_domain", "final_domain"  # URLScan sandbox data
        ]
        for key in domain_keys:
            val = details.get(key)
            if val:
                items = val if isinstance(val, list) else [val]
                for v in items[:10]:
                    if v and isinstance(v, str) and '.' in v and not re.match(r'^\d+\.\d+\.\d+\.\d+$', v):
                        clean = v.lower().strip('.').strip()
                        if len(clean) > 3:
                            related["domains"].append({"value": clean, "source": source_name, "reason": key})
        
        # Extract domain from final_url
        final_url = details.get("final_url") or details.get("last_final_url")
        if final_url and isinstance(final_url, str):
            from urllib.parse import urlparse
            try:
                parsed = urlparse(final_url)
                if parsed.netloc:
                    related["domains"].append({"value": parsed.netloc.lower(), "source": source_name, "reason": "final_url"})
            except:
                pass
        
        # === IPs ===
        ip_keys = ["a_records", "ip", "resolutions", "hosts", "contacted_ips", "c2_ips", 
                   "page_ip", "ip_address", "server_ip"]  # URLScan/IPQS sandbox data
        for key in ip_keys:
            val = details.get(key)
            if val:
                items = val if isinstance(val, list) else [val]
                for v in items[:10]:
                    ip_val = v.get("ip_address") if isinstance(v, dict) else v
                    if ip_val and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(ip_val)):
                        related["ips"].append({"value": str(ip_val), "source": source_name, "reason": key})
        
        # === HASHES ===
        hash_keys = ["hashes", "malware_samples", "related_hashes", "md5", "sha1", "sha256"]
        for key in hash_keys:
            val = details.get(key)
            if val:
                items = val if isinstance(val, list) else [val]
                for v in items[:5]:
                    if isinstance(v, str) and re.match(r'^[a-fA-F0-9]{32,64}$', v):
                        related["hashes"].append({"value": v, "source": source_name, "reason": key})
        
        # === URLs ===
        url_keys = ["distribution_urls", "urls", "c2_urls", "download_url", "reference"]
        for key in url_keys:
            val = details.get(key)
            if val:
                items = val if isinstance(val, list) else [val]
                for v in items[:10]:
                    url_str = v.get("url") if isinstance(v, dict) else v
                    if url_str and isinstance(url_str, str) and ("http://" in url_str or "https://" in url_str):
                        related["urls"].append({"value": url_str, "source": source_name, "reason": key})
        
        # === FILES ===
        file_keys = ["filenames", "file_name", "submit_name", "filename"]
        for key in file_keys:
            val = details.get(key)
            if val:
                items = val if isinstance(val, list) else [val]
                for v in items[:5]:
                    if v and isinstance(v, str) and len(v) > 2:
                        related["files"].append({"value": v, "source": source_name, "reason": key})
    
    # Deduplicate
    for key in related:
        seen = set()
        unique = []
        for item in related[key]:
            if item["value"].lower() not in seen:
                seen.add(item["value"].lower())
                unique.append(item)
        related[key] = unique
    
    return related


def build_summary(results: Dict[str, Dict], data_type: str) -> Dict:
    """Build summary based on input type"""
    summary = {
        "type": data_type,
        "threat_scores": [],
        # IP-specific
        "locations": {},
        "isps": {},
        "asns": {},
        "flags": {},
        # Hash-specific
        "file_type": {},
        "threat_names": {},
        "signatures": {},
        "filenames": [],
        # Domain-specific
        "registrar": {},
        "dns_records": {},
        "email_security": {"spf": [], "dmarc": [], "dkim": []},
        # URL-specific
        "categories": {},
        "final_urls": [],
    }
    
    for source_name, result in results.items():
        details = result.get("details", {})
        score = result.get("score")
        
        # Threat scores for all types
        if score is not None and score > 0:
            summary["threat_scores"].append({"source": source_name, "score": score})
        
        if data_type == "ip":
            # Location
            country = details.get("country") or details.get("country_name") or details.get("country_code")
            if country:
                normalized = normalize_country(country)
                if normalized:
                    if normalized not in summary["locations"]:
                        summary["locations"][normalized] = []
                    summary["locations"][normalized].append(source_name)
            
            # ISP
            isp = details.get("isp") or details.get("organisation") or details.get("as_owner") or details.get("org")
            if isp:
                if isp not in summary["isps"]:
                    summary["isps"][isp] = []
                summary["isps"][isp].append(source_name)
            
            # ASN
            asn = details.get("asn") or details.get("as_number")
            as_name = details.get("as_name") or details.get("as_owner")
            if asn:
                asn_str = str(asn).replace("AS", "")
                key = f"AS{asn_str}"
                if as_name:
                    key += f" ({as_name[:25]})"
                if key not in summary["asns"]:
                    summary["asns"][key] = []
                summary["asns"][key].append(source_name)
            
            # Flags
            flag_checks = [
                ("is_proxy", "proxy", "Proxy"),
                ("is_vpn", "vpn", "VPN"),
                ("is_tor", "tor", "TOR"),
                ("noise", None, "Scanner"),
                ("is_hosting", "hosting", "Hosting"),
                ("is_mobile", "mobile", "Mobile"),
            ]
            for key1, key2, flag_name in flag_checks:
                if details.get(key1) or (key2 and details.get(key2)):
                    if flag_name not in summary["flags"]:
                        summary["flags"][flag_name] = []
                    if source_name not in summary["flags"][flag_name]:
                        summary["flags"][flag_name].append(source_name)
        
        elif data_type == "hash":
            # Hash type
            ht = details.get("hash_type")
            if ht and "hash_type" not in summary:
                summary["hash_type"] = ht
            
            # File type
            ft = details.get("file_type") or details.get("type_description") or details.get("type")
            if ft:
                if ft not in summary["file_type"]:
                    summary["file_type"][ft] = []
                summary["file_type"][ft].append(source_name)
            
            # Threat name/signature
            sig = details.get("signature") or details.get("threat_label") or details.get("malware") or details.get("vx_family")
            if sig:
                if sig not in summary["signatures"]:
                    summary["signatures"][sig] = []
                summary["signatures"][sig].append(source_name)
            
            # CVEs
            cves = details.get("cves", [])
            if cves:
                if "cves" not in summary:
                    summary["cves"] = []
                summary["cves"].extend(cves)
            
            # Sandbox verdicts
            for sandbox_key in ["anyrun_verdict", "cape_verdict", "vmray_verdict", "verdict"]:
                verdict = details.get(sandbox_key)
                if verdict:
                    if "sandbox_verdicts" not in summary:
                        summary["sandbox_verdicts"] = {}
                    sandbox_name = sandbox_key.replace("_verdict", "").upper()
                    if sandbox_name not in summary["sandbox_verdicts"]:
                        summary["sandbox_verdicts"][sandbox_name] = []
                    summary["sandbox_verdicts"][sandbox_name].append(verdict)
            
            # Sandbox links - from MalwareBazaar's sandbox_links dict
            sandbox_links_dict = details.get("sandbox_links", {})
            if sandbox_links_dict and isinstance(sandbox_links_dict, dict):
                if "sandbox_links" not in summary:
                    summary["sandbox_links"] = {}
                summary["sandbox_links"].update(sandbox_links_dict)
            
            # Also check for individual link fields
            for link_key in ["anyrun_link", "analysis_url"]:
                link = details.get(link_key)
                if link:
                    if "sandbox_links" not in summary:
                        summary["sandbox_links"] = {}
                    if "ANY.RUN" not in summary["sandbox_links"]:
                        summary["sandbox_links"]["ANY.RUN"] = link
            
            # Vendor intel
            vendor_intel = details.get("vendor_intel", [])
            if vendor_intel:
                if "vendor_intel" not in summary:
                    summary["vendor_intel"] = set()
                summary["vendor_intel"].update(vendor_intel)
            
            # YARA rules
            yara_rules = details.get("yara_rules", [])
            if yara_rules:
                if "yara_rules" not in summary:
                    summary["yara_rules"] = []
                summary["yara_rules"].extend(yara_rules)
            
            # Threat names/tags
            for tn in details.get("threat_names", []) + details.get("tags", []):
                if tn and tn not in summary["threat_names"]:
                    summary["threat_names"][tn] = []
                if tn:
                    summary["threat_names"][tn].append(source_name)
            
            # Filenames
            for fn in details.get("filenames", []):
                if fn and fn not in summary["filenames"]:
                    summary["filenames"].append(fn)
            
            # File Metadata (from VirusTotal PE info)
            for field in ["product", "company", "copyright", "description", "file_version", "signing_date", "signers", "original_name"]:
                value = details.get(field)
                if value:
                    if field not in summary:
                        summary[field] = []
                    if value not in summary[field]:
                        summary[field].append(value)
        
        elif data_type == "domain":
            # Registrar with source
            reg = details.get("registrar")
            if reg:
                if reg not in summary["registrar"]:
                    summary["registrar"][reg] = []
                if source_name not in summary["registrar"][reg]:
                    summary["registrar"][reg].append(source_name)
            
            # Creation/Expiry dates with source tracking
            for date_key in ["creation_date", "created", "registered"]:
                date_val = details.get(date_key)
                if date_val:
                    if "creation_date" not in summary:
                        summary["creation_date"] = {}
                    date_str = str(date_val)[:10]
                    if date_str not in summary["creation_date"]:
                        summary["creation_date"][date_str] = []
                    if source_name not in summary["creation_date"][date_str]:
                        summary["creation_date"][date_str].append(source_name)
            
            for date_key in ["expiry_date", "expires", "expiration"]:
                date_val = details.get(date_key)
                if date_val:
                    if "expiry_date" not in summary:
                        summary["expiry_date"] = {}
                    date_str = str(date_val)[:10]
                    if date_str not in summary["expiry_date"]:
                        summary["expiry_date"][date_str] = []
                    if source_name not in summary["expiry_date"][date_str]:
                        summary["expiry_date"][date_str].append(source_name)
            
            # DNS Records with source tracking (from DNS lookups)
            for rec_type in ["a_records", "mx_records", "ns_records", "txt_records"]:
                recs = details.get(rec_type, [])
                if recs:
                    if rec_type not in summary["dns_records"]:
                        summary["dns_records"][rec_type] = {}
                    for rec in recs:
                        if rec not in summary["dns_records"][rec_type]:
                            summary["dns_records"][rec_type][rec] = []
                        if source_name not in summary["dns_records"][rec_type][rec]:
                            summary["dns_records"][rec_type][rec].append(source_name)
            
            # WHOIS nameservers (stored as "nameservers" not "ns_records")
            whois_ns = details.get("nameservers", [])
            if whois_ns:
                if "ns_records" not in summary["dns_records"]:
                    summary["dns_records"]["ns_records"] = {}
                for ns in whois_ns:
                    ns_lower = ns.lower() if isinstance(ns, str) else ns
                    if ns_lower not in summary["dns_records"]["ns_records"]:
                        summary["dns_records"]["ns_records"][ns_lower] = []
                    if source_name not in summary["dns_records"]["ns_records"][ns_lower]:
                        summary["dns_records"]["ns_records"][ns_lower].append(source_name)
            
            # Registrant info
            reg_name = details.get("registrant_name")
            if reg_name:
                if "registrant_name" not in summary:
                    summary["registrant_name"] = {}
                if reg_name not in summary["registrant_name"]:
                    summary["registrant_name"][reg_name] = []
                if source_name not in summary["registrant_name"][reg_name]:
                    summary["registrant_name"][reg_name].append(source_name)
            
            reg_org = details.get("registrant_org")
            if reg_org:
                if "registrant_org" not in summary:
                    summary["registrant_org"] = {}
                if reg_org not in summary["registrant_org"]:
                    summary["registrant_org"][reg_org] = []
                if source_name not in summary["registrant_org"][reg_org]:
                    summary["registrant_org"][reg_org].append(source_name)
            
            # Domain status
            status = details.get("status", [])
            if status:
                if "domain_status" not in summary:
                    summary["domain_status"] = {}
                for s in (status if isinstance(status, list) else [status]):
                    if s not in summary["domain_status"]:
                        summary["domain_status"][s] = []
                    if source_name not in summary["domain_status"][s]:
                        summary["domain_status"][s].append(source_name)
            
            # Store SPF/DMARC record content with source
            if details.get("spf_record"):
                if "spf_record" not in summary:
                    summary["spf_record"] = {"value": details.get("spf_record"), "source": source_name}
            if details.get("dmarc_record"):
                if "dmarc_record" not in summary:
                    summary["dmarc_record"] = {"value": details.get("dmarc_record"), "source": source_name}
            
            # Email security flags
            if details.get("has_spf"):
                summary["email_security"]["spf"].append(source_name)
            if details.get("has_dmarc"):
                summary["email_security"]["dmarc"].append(source_name)
            if details.get("has_dkim"):
                summary["email_security"]["dkim"].append(source_name)
            
            # Subdomains with source tracking
            subdomains = details.get("subdomains", [])
            if subdomains:
                if "subdomains" not in summary:
                    summary["subdomains"] = {}
                for sub in subdomains[:20]:
                    if sub not in summary["subdomains"]:
                        summary["subdomains"][sub] = []
                    if source_name not in summary["subdomains"][sub]:
                        summary["subdomains"][sub].append(source_name)
            
            # Certificates with source
            certs = details.get("certificates", []) or details.get("cert_names", [])
            if certs:
                if "certificates" not in summary:
                    summary["certificates"] = {}
                for cert in certs[:10]:
                    if cert not in summary["certificates"]:
                        summary["certificates"][cert] = []
                    if source_name not in summary["certificates"][cert]:
                        summary["certificates"][cert].append(source_name)
            
            # Country with source
            country = details.get("country") or details.get("registrant_country")
            if country:
                if "country" not in summary:
                    summary["country"] = {}
                if country not in summary["country"]:
                    summary["country"][country] = []
                if source_name not in summary["country"][country]:
                    summary["country"][country].append(source_name)
            
            # Scanner/Threat results
            threat_score = details.get("threat_score") or details.get("risk_score")
            if threat_score:
                if "threat_scores" not in summary:
                    summary["threat_scores"] = {}
                summary["threat_scores"][source_name] = threat_score
            
            # Malicious detections
            detections = details.get("detections") or details.get("positives")
            if detections:
                if "detections" not in summary:
                    summary["detections"] = {}
                summary["detections"][source_name] = detections
            
            # Categories
            cats = details.get("categories") or details.get("category")
            if cats:
                if "domain_categories" not in summary:
                    summary["domain_categories"] = {}
                if isinstance(cats, dict):
                    for cat in cats.values():
                        if cat:
                            if cat not in summary["domain_categories"]:
                                summary["domain_categories"][cat] = []
                            if source_name not in summary["domain_categories"][cat]:
                                summary["domain_categories"][cat].append(source_name)
                elif isinstance(cats, str):
                    if cats not in summary["domain_categories"]:
                        summary["domain_categories"][cats] = []
                    if source_name not in summary["domain_categories"][cats]:
                        summary["domain_categories"][cats].append(source_name)
        
        elif data_type == "url":
            # Categories
            cats = details.get("categories", {}) or details.get("category")
            if cats:
                if isinstance(cats, dict):
                    for cat in cats.values():
                        if cat and cat not in summary["categories"]:
                            summary["categories"][cat] = []
                        if cat:
                            summary["categories"][cat].append(source_name)
                elif isinstance(cats, str):
                    if cats not in summary["categories"]:
                        summary["categories"][cats] = []
                    summary["categories"][cats].append(source_name)
            
            # Final URL
            final = details.get("final_url") or details.get("last_final_url")
            if final and final not in summary["final_urls"]:
                summary["final_urls"].append(final)
            
            # Sandbox page info (URLScan, IPQS)
            page_domain = details.get("page_domain") or details.get("domain")
            if page_domain:
                if "page_domains" not in summary:
                    summary["page_domains"] = {}
                if page_domain not in summary["page_domains"]:
                    summary["page_domains"][page_domain] = []
                if source_name not in summary["page_domains"][page_domain]:
                    summary["page_domains"][page_domain].append(source_name)
            
            page_ip = details.get("page_ip") or details.get("ip_address")
            if page_ip:
                if "page_ips" not in summary:
                    summary["page_ips"] = {}
                if page_ip not in summary["page_ips"]:
                    summary["page_ips"][page_ip] = []
                if source_name not in summary["page_ips"][page_ip]:
                    summary["page_ips"][page_ip].append(source_name)
            
            page_country = details.get("page_country") or details.get("country_code")
            if page_country:
                if "page_countries" not in summary:
                    summary["page_countries"] = {}
                if page_country not in summary["page_countries"]:
                    summary["page_countries"][page_country] = []
                if source_name not in summary["page_countries"][page_country]:
                    summary["page_countries"][page_country].append(source_name)
            
            page_server = details.get("page_server")
            if page_server:
                if "page_servers" not in summary:
                    summary["page_servers"] = {}
                if page_server not in summary["page_servers"]:
                    summary["page_servers"][page_server] = []
                if source_name not in summary["page_servers"][page_server]:
                    summary["page_servers"][page_server].append(source_name)
            
            # Threat flags
            if details.get("phishing"):
                if "url_flags" not in summary:
                    summary["url_flags"] = {}
                if "Phishing" not in summary["url_flags"]:
                    summary["url_flags"]["Phishing"] = []
                summary["url_flags"]["Phishing"].append(source_name)
            
            if details.get("malware"):
                if "url_flags" not in summary:
                    summary["url_flags"] = {}
                if "Malware" not in summary["url_flags"]:
                    summary["url_flags"]["Malware"] = []
                summary["url_flags"]["Malware"].append(source_name)
            
            if details.get("suspicious"):
                if "url_flags" not in summary:
                    summary["url_flags"] = {}
                if "Suspicious" not in summary["url_flags"]:
                    summary["url_flags"]["Suspicious"] = []
                summary["url_flags"]["Suspicious"].append(source_name)
            
            # Threat/malware info
            threat = details.get("threat") or details.get("malware_printable")
            if threat:
                if "url_threats" not in summary:
                    summary["url_threats"] = {}
                if threat not in summary["url_threats"]:
                    summary["url_threats"][threat] = []
                if source_name not in summary["url_threats"][threat]:
                    summary["url_threats"][threat].append(source_name)
            
            # URL status (online/offline)
            status = details.get("status") or details.get("url_status")
            if status:
                if "url_status" not in summary:
                    summary["url_status"] = {}
                if status not in summary["url_status"]:
                    summary["url_status"][status] = []
                if source_name not in summary["url_status"][status]:
                    summary["url_status"][status].append(source_name)
        
        elif data_type == "email":
            # Reputation
            rep = details.get("reputation")
            if rep:
                if "reputation" not in summary:
                    summary["reputation"] = {}
                if rep not in summary["reputation"]:
                    summary["reputation"][rep] = []
                if source_name not in summary["reputation"][rep]:
                    summary["reputation"][rep].append(source_name)
            
            # Suspicious/malicious flags
            if details.get("suspicious"):
                if "email_flags" not in summary:
                    summary["email_flags"] = {}
                if "Suspicious" not in summary["email_flags"]:
                    summary["email_flags"]["Suspicious"] = []
                summary["email_flags"]["Suspicious"].append(source_name)
            
            if details.get("malicious_activity"):
                if "email_flags" not in summary:
                    summary["email_flags"] = {}
                if "Malicious" not in summary["email_flags"]:
                    summary["email_flags"]["Malicious"] = []
                summary["email_flags"]["Malicious"].append(source_name)
            
            if details.get("spam"):
                if "email_flags" not in summary:
                    summary["email_flags"] = {}
                if "Spam" not in summary["email_flags"]:
                    summary["email_flags"]["Spam"] = []
                summary["email_flags"]["Spam"].append(source_name)
            
            if details.get("blacklisted"):
                if "email_flags" not in summary:
                    summary["email_flags"] = {}
                if "Blacklisted" not in summary["email_flags"]:
                    summary["email_flags"]["Blacklisted"] = []
                summary["email_flags"]["Blacklisted"].append(source_name)
            
            # Disposable check
            if details.get("disposable"):
                if "email_flags" not in summary:
                    summary["email_flags"] = {}
                if "Disposable" not in summary["email_flags"]:
                    summary["email_flags"]["Disposable"] = []
                summary["email_flags"]["Disposable"].append(source_name)
            
            # Breaches
            breaches = details.get("breaches") or details.get("breach_details")
            breach_count = details.get("breach_count", 0)
            if breaches or breach_count:
                if "breaches" not in summary:
                    summary["breaches"] = {"count": 0, "sources": [], "names": []}
                summary["breaches"]["count"] = max(summary["breaches"]["count"], breach_count if breach_count else len(breaches))
                summary["breaches"]["sources"].append(source_name)
                if isinstance(breaches, list):
                    for b in breaches[:5]:
                        name = b.get("name") if isinstance(b, dict) else b
                        if name and name not in summary["breaches"]["names"]:
                            summary["breaches"]["names"].append(name)
            
            # Leak records
            leak_count = details.get("found") or details.get("total")
            if leak_count:
                if "leaks" not in summary:
                    summary["leaks"] = {"count": 0, "sources": []}
                summary["leaks"]["count"] = max(summary["leaks"]["count"], leak_count)
                summary["leaks"]["sources"].append(source_name)
            
            # Domain info
            domain = details.get("domain")
            if domain:
                if "email_domain" not in summary:
                    summary["email_domain"] = domain
            
            domain_age = details.get("age_years") or details.get("age_days")
            if domain_age:
                if "domain_age" not in summary:
                    summary["domain_age"] = {"value": domain_age, "source": source_name}
            
            # MX records
            mx = details.get("mx_records") or details.get("has_mx")
            if mx:
                if "mx_records" not in summary:
                    summary["mx_records"] = {"records": [], "source": source_name}
                if isinstance(mx, list):
                    summary["mx_records"]["records"] = mx[:3]
                elif mx == True:
                    summary["mx_records"]["has_mx"] = True
            
            # Free provider
            if details.get("free_provider") or details.get("webmail"):
                if "email_type" not in summary:
                    summary["email_type"] = "Free/Webmail"
            
            # Deliverable
            deliverable = details.get("deliverable")
            if deliverable is not None:
                if "deliverable" not in summary:
                    summary["deliverable"] = {"status": deliverable, "source": source_name}
            
            # Profiles found
            profiles = details.get("profiles", [])
            if profiles:
                if "profiles" not in summary:
                    summary["profiles"] = []
                for p in profiles:
                    if p not in summary["profiles"]:
                        summary["profiles"].append(p)
    
    return summary


def render_summary(summary: Dict, data_type: str):
    """Render type-aware summary"""
    st.markdown("## Summary")
    
    if data_type == "ip":
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("**Location**")
            if summary["locations"]:
                for loc, sources in sorted(summary["locations"].items(), key=lambda x: len(x[1]), reverse=True)[:2]:
                    st.markdown(f"`{loc}`")
                    st.caption(f"({', '.join(sources[:2])})")
            else:
                st.markdown("*Unknown*")
        
        with col2:
            st.markdown("**ISP / Org**")
            if summary["isps"]:
                for isp, sources in sorted(summary["isps"].items(), key=lambda x: len(x[1]), reverse=True)[:1]:
                    st.markdown(f"`{isp[:25]}`")
                    st.caption(f"({', '.join(sources[:2])})")
            else:
                st.markdown("*Unknown*")
        
        with col3:
            st.markdown("**ASN**")
            if summary["asns"]:
                for asn, sources in list(summary["asns"].items())[:1]:
                    st.markdown(f"`{asn[:30]}`")
                    st.caption(f"({', '.join(sources[:2])})")
            else:
                st.markdown("*Unknown*")
        
        with col4:
            st.markdown("**Flags**")
            if summary["flags"]:
                for flag, sources in summary["flags"].items():
                    st.markdown(f"`{flag}` ({', '.join(sources[:2])})")
            else:
                st.markdown("*None*")
    
    elif data_type == "hash":
        # Row 1: Basic File Info
        st.markdown("#### Basic Info")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("**Hash Type**")
            if summary.get("hash_type"):
                st.markdown(f"`{summary['hash_type']}`")
            else:
                st.markdown("*SHA256/MD5/SHA1*")
        
        with col2:
            st.markdown("**File Type**")
            if summary["file_type"]:
                for ft, sources in list(summary["file_type"].items())[:1]:
                    st.markdown(f"`{ft[:30]}`")
            else:
                st.markdown("*Unknown*")
        
        with col3:
            st.markdown("**Threat Name**")
            if summary["signatures"]:
                for sig, sources in list(summary["signatures"].items())[:1]:
                    st.markdown(f"`{sig[:30]}`")
            else:
                st.markdown("*Unknown*")
        
        with col4:
            st.markdown("**CVE**")
            if summary.get("cves"):
                unique_cves = list(set(summary["cves"]))[:3]
                st.markdown(f"`{', '.join(unique_cves)}`")
            else:
                st.markdown("*None*")
        
        # Row 2: File Metadata / Signature Info
        st.markdown("#### File Metadata")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("**Product**")
            if summary.get("product"):
                st.markdown(f"`{summary['product'][0][:25]}`")
            else:
                st.markdown("*Unknown*")
        
        with col2:
            st.markdown("**Company / Copyright**")
            if summary.get("company"):
                st.markdown(f"`{summary['company'][0][:25]}`")
            elif summary.get("copyright"):
                st.markdown(f"`{summary['copyright'][0][:25]}`")
            else:
                st.markdown("*Unknown*")
        
        with col3:
            st.markdown("**Description**")
            if summary.get("description"):
                st.markdown(f"`{summary['description'][0][:30]}`")
            else:
                st.markdown("*None*")
        
        with col4:
            st.markdown("**File Version**")
            if summary.get("file_version"):
                st.markdown(f"`{summary['file_version'][0][:20]}`")
            else:
                st.markdown("*Unknown*")
        
        # Row 3: Signature / Signing Info
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("**Signing Date**")
            if summary.get("signing_date"):
                st.markdown(f"`{summary['signing_date'][0][:20]}`")
            else:
                st.markdown("*Not signed*")
        
        with col2:
            st.markdown("**Signer**")
            if summary.get("signers"):
                st.markdown(f"`{summary['signers'][0][:25]}`")
            else:
                st.markdown("*None*")
        
        with col3:
            st.markdown("**Original Name**")
            if summary.get("original_name"):
                st.markdown(f"`{summary['original_name'][0][:25]}`")
            else:
                st.markdown("*Unknown*")
        
        with col4:
            st.markdown("**Filenames**")
            if summary["filenames"]:
                st.markdown(f"`{summary['filenames'][0][:25]}`")
                if len(summary["filenames"]) > 1:
                    st.caption(f"+{len(summary['filenames'])-1} more")
            else:
                st.markdown("*Unknown*")
        
        # Row 4: Threat Intel
        st.markdown("#### Threat Intelligence")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("**Sandbox Verdicts**")
            if summary.get("sandbox_verdicts"):
                for sandbox, verdicts in list(summary["sandbox_verdicts"].items())[:3]:
                    verdict = verdicts[0] if verdicts else "unknown"
                    color = "red" if verdict == "malicious" else "orange" if verdict == "suspicious" else "green"
                    st.markdown(f"**{sandbox}**: :{color}[{verdict}]")
            else:
                st.markdown("*No sandbox data*")
        
        with col2:
            st.markdown("**Vendor Intel**")
            if summary.get("vendor_intel"):
                vendors = list(summary["vendor_intel"])[:4]
                st.markdown(f"`{', '.join(vendors)}`")
            else:
                st.markdown("*None*")
        
        with col3:
            st.markdown("**Tags**")
            if summary["threat_names"]:
                tags = list(summary["threat_names"].keys())[:5]
                st.markdown(f"`{', '.join(tags)}`")
            else:
                st.markdown("*None*")
        
        with col4:
            st.markdown("**YARA Rules**")
            if summary.get("yara_rules"):
                rules = list(set(summary["yara_rules"]))[:3]
                st.markdown(f"`{', '.join(rules)}`")
            else:
                st.markdown("*None*")
        
        # Row 5: Links
        st.markdown("#### Sandbox Links")
        if summary.get("sandbox_links"):
            links = summary["sandbox_links"]
            if isinstance(links, dict):
                cols = st.columns(min(len(links), 6))
                for i, (vendor, link) in enumerate(list(links.items())[:6]):
                    with cols[i]:
                        st.markdown(f"[{vendor}]({link})")
            else:
                st.markdown(", ".join([f"[Link]({l})" for l in links[:4]]))
        else:
            st.markdown("*No sandbox links available*")
    
    elif data_type == "domain":
        # Row 1: WHOIS Info
        st.markdown("#### Registration Info")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("**Registrar**")
            if summary["registrar"]:
                for reg, sources in list(summary["registrar"].items())[:1]:
                    st.markdown(f"`{reg[:25]}`")
                    st.caption(f"({', '.join(sources[:2])})")
            else:
                st.markdown("*Unknown*")
        
        with col2:
            st.markdown("**Created**")
            if summary.get("creation_date") and isinstance(summary["creation_date"], dict):
                for date_str, sources in list(summary["creation_date"].items())[:1]:
                    st.markdown(f"`{date_str}`")
                    st.caption(f"({', '.join(sources[:2])})")
            else:
                st.markdown("*Unknown*")
        
        with col3:
            st.markdown("**Expires**")
            if summary.get("expiry_date") and isinstance(summary["expiry_date"], dict):
                for date_str, sources in list(summary["expiry_date"].items())[:1]:
                    st.markdown(f"`{date_str}`")
                    st.caption(f"({', '.join(sources[:2])})")
            else:
                st.markdown("*Unknown*")
        
        with col4:
            st.markdown("**Registrant Org**")
            if summary.get("registrant_org") and isinstance(summary["registrant_org"], dict):
                for org, sources in list(summary["registrant_org"].items())[:1]:
                    st.markdown(f"`{org[:20]}`")
                    st.caption(f"({', '.join(sources[:2])})")
            elif summary.get("registrant_name") and isinstance(summary["registrant_name"], dict):
                for name, sources in list(summary["registrant_name"].items())[:1]:
                    st.markdown(f"`{name[:20]}`")
                    st.caption(f"({', '.join(sources[:2])})")
            else:
                st.markdown("*Unknown*")
        
        # Row 2: DNS Records
        st.markdown("#### DNS Records")
        col1, col2, col3, col4 = st.columns(4)
        
        dns = summary["dns_records"]
        
        with col1:
            st.markdown("**A Records (IPs)**")
            a_recs = dns.get("a_records", {})
            if isinstance(a_recs, dict) and a_recs:
                for ip, sources in list(a_recs.items())[:3]:
                    st.markdown(f"`{ip}` ({', '.join(sources)})")
                if len(a_recs) > 3:
                    st.caption(f"+{len(a_recs)-3} more")
            else:
                st.markdown("*None*")
        
        with col2:
            st.markdown("**MX Records (Mail)**")
            mx_recs = dns.get("mx_records", {})
            if isinstance(mx_recs, dict) and mx_recs:
                for mx, sources in list(mx_recs.items())[:3]:
                    clean_mx = mx.split()[-1] if ' ' in mx else mx
                    st.markdown(f"`{clean_mx[:20]}` ({', '.join(sources)})")
            else:
                st.markdown("*None*")
        
        with col3:
            st.markdown("**NS Records**")
            ns_recs = dns.get("ns_records", {})
            if isinstance(ns_recs, dict) and ns_recs:
                for ns, sources in list(ns_recs.items())[:4]:
                    st.markdown(f"`{ns[:22]}` ({', '.join(sources)})")
                if len(ns_recs) > 4:
                    st.caption(f"+{len(ns_recs)-4} more")
            else:
                st.markdown("*None*")
        
        with col4:
            st.markdown("**TXT Records**")
            txt_recs = dns.get("txt_records", {})
            if isinstance(txt_recs, dict) and txt_recs:
                st.markdown(f"`{len(txt_recs)} record(s)`")
                with st.expander("View TXT", expanded=False):
                    for txt, sources in list(txt_recs.items())[:5]:
                        st.markdown(f"- `{txt[:40]}...` ({sources[0]})")
            else:
                st.markdown("*None*")
        
        # Row 3: Email Security
        st.markdown("#### Mail Security")
        col1, col2, col3, col4 = st.columns(4)
        
        es = summary["email_security"]
        
        # Determine SPF strictness
        spf_rec = summary.get("spf_record", {})
        spf_text = ""
        if isinstance(spf_rec, dict) and spf_rec.get("value"):
            spf_text = spf_rec["value"]
        elif isinstance(spf_rec, str):
            spf_text = spf_rec
        
        spf_strict = "none"
        if spf_text:
            if "-all" in spf_text:
                spf_strict = "strict"
            elif "~all" in spf_text:
                spf_strict = "softfail"
            elif "?all" in spf_text or "+all" in spf_text:
                spf_strict = "neutral"
            else:
                spf_strict = "present"
        
        # Determine DMARC policy
        dmarc_rec = summary.get("dmarc_record", {})
        dmarc_text = ""
        if isinstance(dmarc_rec, dict) and dmarc_rec.get("value"):
            dmarc_text = dmarc_rec["value"]
        elif isinstance(dmarc_rec, str):
            dmarc_text = dmarc_rec
        
        dmarc_policy = "none"
        if dmarc_text:
            if "p=reject" in dmarc_text:
                dmarc_policy = "reject"
            elif "p=quarantine" in dmarc_text:
                dmarc_policy = "quarantine"
            elif "p=none" in dmarc_text:
                dmarc_policy = "none"
        
        has_dkim = bool(es["dkim"])
        has_spf = bool(es["spf"])
        has_dmarc = bool(es["dmarc"])
        
        with col1:
            # Combined Mail Security Score
            st.markdown("**Mail Security**")
            if dmarc_policy == "reject" and has_dkim:
                st.markdown(":green[Strong]")
                st.caption("DMARC reject + DKIM")
            elif dmarc_policy == "quarantine" or (has_spf and spf_strict == "strict"):
                st.markdown(":orange[Moderate]")
                reason = f"DMARC {dmarc_policy}" if has_dmarc else f"SPF {spf_strict}"
                st.caption(reason)
            elif has_spf or has_dmarc:
                st.markdown(":orange[Basic]")
                st.caption("Partial config")
            else:
                st.markdown(":red[Weak]")
                st.caption("No SPF/DMARC")
        
        with col2:
            st.markdown("**DMARC Policy**")
            if has_dmarc:
                color = "green" if dmarc_policy == "reject" else "orange" if dmarc_policy == "quarantine" else "red"
                st.markdown(f":{color}[{dmarc_policy.upper()}]")
                if dmarc_text:
                    st.caption(f"{dmarc_text[:50]}{'...' if len(dmarc_text) > 50 else ''}")
            else:
                st.markdown(":red[Not Configured]")
        
        with col3:
            st.markdown("**DKIM**")
            if has_dkim:
                st.markdown(":green[Configured]")
                st.caption(f"({', '.join(es['dkim'][:2])})")
            else:
                st.markdown(":orange[Not Detected]")
        
        with col4:
            # Detect mail provider from MX
            st.markdown("**Mail Provider**")
            mx_recs = dns.get("mx_records", {})
            provider = "Unknown"
            for mx in mx_recs.keys() if isinstance(mx_recs, dict) else mx_recs:
                mx_lower = mx.lower()
                if "google" in mx_lower or "gmail" in mx_lower:
                    provider = "Google Workspace"
                    break
                elif "outlook" in mx_lower or "microsoft" in mx_lower:
                    provider = "Microsoft 365"
                    break
                elif "zoho" in mx_lower:
                    provider = "Zoho Mail"
                    break
                elif "protonmail" in mx_lower:
                    provider = "ProtonMail"
                    break
                elif "mimecast" in mx_lower:
                    provider = "Mimecast"
                    break
                elif "amazonses" in mx_lower or "aws" in mx_lower:
                    provider = "Amazon SES"
                    break
                elif "yahoo" in mx_lower:
                    provider = "Yahoo Mail"
                    break
                elif "fastmail" in mx_lower:
                    provider = "Fastmail"
                    break
            st.markdown(f"`{provider}`")
        
        # Row 4: Subdomains & Certificates
        st.markdown("#### Discovery & Threat Info")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("**Subdomains**")
            subs = summary.get("subdomains", {})
            if isinstance(subs, dict) and subs:
                st.markdown(f"`{len(subs)} found`")
                # Show list in expander
                with st.expander("View all", expanded=False):
                    for sub, sources in list(subs.items())[:15]:
                        st.markdown(f"- `{sub}` ({', '.join(sources)})")
            else:
                st.markdown("*None found*")
        
        with col2:
            st.markdown("**Certificates**")
            certs = summary.get("certificates", {})
            if isinstance(certs, dict) and certs:
                st.markdown(f"`{len(certs)} cert(s)`")
                with st.expander("View certs", expanded=False):
                    for cert, sources in list(certs.items())[:10]:
                        st.markdown(f"- `{cert[:30]}` ({sources[0]})")
            else:
                st.markdown("*None*")
        
        with col3:
            st.markdown("**Threat Scores**")
            scores = summary.get("threat_scores", {})
            detections = summary.get("detections", {})
            has_data = False
            if isinstance(scores, dict) and scores:
                for src, score in list(scores.items())[:2]:
                    color = "red" if score >= 50 else "orange" if score >= 20 else "green"
                    st.markdown(f":{color}[{score}] ({src})")
                    has_data = True
            if isinstance(detections, dict) and detections:
                for src, det in list(detections.items())[:2]:
                    st.markdown(f"`{det} detections` ({src})")
                    has_data = True
            if not has_data:
                st.markdown("*Clean*")
        
        with col4:
            st.markdown("**Categories**")
            cats = summary.get("domain_categories", {})
            if isinstance(cats, dict) and cats:
                for cat, sources in list(cats.items())[:3]:
                    st.markdown(f"`{cat}` ({sources[0]})")
            else:
                st.markdown("*Uncategorized*")
    
    elif data_type == "url":
        # Row 1: Page/Sandbox Info
        st.markdown("#### URL Analysis")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("**Page Domain**")
            page_doms = summary.get("page_domains", {})
            if isinstance(page_doms, dict) and page_doms:
                for dom, sources in list(page_doms.items())[:1]:
                    st.markdown(f"`{dom}`")
                    st.caption(f"({', '.join(sources)})")
            else:
                st.markdown("*Unknown*")
        
        with col2:
            st.markdown("**Page IP**")
            page_ips = summary.get("page_ips", {})
            if isinstance(page_ips, dict) and page_ips:
                for ip, sources in list(page_ips.items())[:1]:
                    st.markdown(f"`{ip}`")
                    st.caption(f"({', '.join(sources)})")
            else:
                st.markdown("*Unknown*")
        
        with col3:
            st.markdown("**Country**")
            countries = summary.get("page_countries", {})
            if isinstance(countries, dict) and countries:
                for c, sources in list(countries.items())[:1]:
                    st.markdown(f"`{c}`")
                    st.caption(f"({', '.join(sources)})")
            else:
                st.markdown("*Unknown*")
        
        with col4:
            st.markdown("**Status**")
            statuses = summary.get("url_status", {})
            if isinstance(statuses, dict) and statuses:
                for status, sources in list(statuses.items())[:1]:
                    color = "red" if status == "online" else "green" if status == "offline" else "blue"
                    st.markdown(f":{color}[{status}]")
                    st.caption(f"({', '.join(sources)})")
            else:
                st.markdown("*Unknown*")
        
        # Row 2: Threat Info
        st.markdown("#### Threat Info")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("**Threat Flags**")
            flags = summary.get("url_flags", {})
            if isinstance(flags, dict) and flags:
                for flag, sources in list(flags.items())[:3]:
                    st.markdown(f":red[{flag}] ({sources[0]})")
            else:
                st.markdown(":green[None]")
        
        with col2:
            st.markdown("**Threat Type**")
            threats = summary.get("url_threats", {})
            if isinstance(threats, dict) and threats:
                for threat, sources in list(threats.items())[:2]:
                    st.markdown(f"`{threat}`")
                    st.caption(f"({', '.join(sources)})")
            else:
                st.markdown("*None*")
        
        with col3:
            st.markdown("**Final URL**")
            if summary["final_urls"]:
                for url in summary["final_urls"][:1]:
                    st.code(url[:40] + "..." if len(url) > 40 else url)
            else:
                st.markdown("*Same as input*")
        
        with col4:
            st.markdown("**Categories**")
            if isinstance(summary["categories"], dict) and summary["categories"]:
                for cat, sources in list(summary["categories"].items())[:2]:
                    st.markdown(f"`{cat}` ({sources[0]})")
            else:
                st.markdown("*Unknown*")
    
    elif data_type == "email":
        # Row 1: Email Info
        st.markdown("#### Email Analysis")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("**Reputation**")
            rep = summary.get("reputation", {})
            if isinstance(rep, dict) and rep:
                for r, sources in list(rep.items())[:1]:
                    r_str = str(r)
                    color = "red" if r_str == "low" else "orange" if r_str == "medium" else "green"
                    st.markdown(f":{color}[{r_str.title()}]")
                    st.caption(f"({', '.join(sources)})")
            else:
                st.markdown("*Unknown*")
        
        with col2:
            st.markdown("**Flags**")
            flags = summary.get("email_flags", {})
            if isinstance(flags, dict) and flags:
                for flag, sources in list(flags.items())[:3]:
                    st.markdown(f":red[{flag}] ({sources[0][:8]})")
            else:
                st.markdown(":green[Clean]")
        
        with col3:
            st.markdown("**Breaches**")
            breaches = summary.get("breaches")
            if breaches:
                count = breaches.get("count", 0)
                color = "red" if count >= 5 else "orange" if count >= 1 else "green"
                st.markdown(f":{color}[{count} breaches]")
                names = breaches.get("names", [])[:2]
                if names:
                    st.caption(", ".join(names[:2]))
            else:
                st.markdown(":green[None]")
        
        with col4:
            st.markdown("**Leaks**")
            leaks = summary.get("leaks")
            if leaks:
                count = leaks.get("count", 0)
                color = "red" if count >= 5 else "orange" if count >= 1 else "green"
                st.markdown(f":{color}[{count} records]")
            else:
                st.markdown(":green[None]")
        
        # Row 2: Domain/Mail Info
        st.markdown("#### Domain & Mail Info")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("**Domain**")
            domain = summary.get("email_domain")
            if domain:
                st.code(domain)
            else:
                st.markdown("*Unknown*")
        
        with col2:
            st.markdown("**Domain Age**")
            age = summary.get("domain_age")
            if age:
                value = age.get("value")
                color = "red" if isinstance(value, int) and value < 1 else "green"
                st.markdown(f":{color}[{value} years]" if isinstance(value, int) and value >= 1 else f":{color}[{value} days]")
            else:
                st.markdown("*Unknown*")
        
        with col3:
            st.markdown("**MX Records**")
            mx = summary.get("mx_records")
            if mx:
                records = mx.get("records", [])
                if records:
                    st.markdown(f"`{records[0][:20]}`")
                    if len(records) > 1:
                        st.caption(f"+{len(records)-1} more")
                else:
                    st.markdown(":green[Has MX]")
            else:
                st.markdown("*No MX*")
        
        with col4:
            st.markdown("**Type**")
            email_type = summary.get("email_type")
            deliverable = summary.get("deliverable")
            if email_type:
                st.markdown(f"`{email_type}`")
            elif deliverable:
                status = deliverable.get("status")
                color = "green" if status else "red"
                st.markdown(f":{color}[{'Deliverable' if status else 'Not Deliverable'}]")
            else:
                st.markdown("*Unknown*")
        
        # Row 3: Mail Security (from domain analysis - these come from domain_summary)
        st.markdown("#### Mail Security")
        col1, col2, col3, col4 = st.columns(4)
        
        # Parse SPF
        spf_rec = summary.get("spf_record")
        spf_text = ""
        if isinstance(spf_rec, dict) and spf_rec.get("value"):
            spf_text = spf_rec["value"]
        elif isinstance(spf_rec, str):
            spf_text = spf_rec
        
        spf_strict = "none"
        has_spf = bool(spf_text)
        if spf_text:
            if "-all" in spf_text:
                spf_strict = "strict"
            elif "~all" in spf_text:
                spf_strict = "softfail"
            elif "?all" in spf_text or "+all" in spf_text:
                spf_strict = "neutral"
            else:
                spf_strict = "present"
        
        # Parse DMARC
        dmarc_rec = summary.get("dmarc_record")
        dmarc_text = ""
        if isinstance(dmarc_rec, dict) and dmarc_rec.get("value"):
            dmarc_text = dmarc_rec["value"]
        elif isinstance(dmarc_rec, str):
            dmarc_text = dmarc_rec
        
        dmarc_policy = "none"
        has_dmarc = bool(dmarc_text)
        if dmarc_text:
            if "p=reject" in dmarc_text:
                dmarc_policy = "reject"
            elif "p=quarantine" in dmarc_text:
                dmarc_policy = "quarantine"
            elif "p=none" in dmarc_text:
                dmarc_policy = "none"
        
        # Check DKIM from email_security or dns_records
        es = summary.get("email_security", {"spf": [], "dmarc": [], "dkim": []})
        has_dkim = bool(es.get("dkim", []))
        
        with col1:
            st.markdown("**Mail Security**")
            if dmarc_policy == "reject" and has_dkim:
                st.markdown(":green[Strong]")
                st.caption("DMARC reject + DKIM")
            elif dmarc_policy == "quarantine" or (has_spf and spf_strict == "strict"):
                st.markdown(":orange[Moderate]")
                reason = f"DMARC {dmarc_policy}" if has_dmarc else f"SPF {spf_strict}"
                st.caption(reason)
            elif has_spf or has_dmarc:
                st.markdown(":orange[Basic]")
                st.caption("Partial config")
            else:
                st.markdown(":red[Weak]")
                st.caption("No SPF/DMARC")
        
        with col2:
            st.markdown("**DMARC Policy**")
            if has_dmarc:
                color = "green" if dmarc_policy == "reject" else "orange" if dmarc_policy == "quarantine" else "red"
                st.markdown(f":{color}[{dmarc_policy.upper()}]")
                if dmarc_text:
                    st.caption(f"{dmarc_text[:50]}{'...' if len(dmarc_text) > 50 else ''}")
            else:
                st.markdown(":orange[Not Found]")
        
        with col3:
            st.markdown("**DKIM**")
            if has_dkim:
                st.markdown(":green[Configured]")
            else:
                st.markdown(":orange[Not Detected]")
        
        with col4:
            # Mail provider from MX records
            st.markdown("**Mail Provider**")
            dns_info = summary.get("dns_records", {})
            mx_recs = dns_info.get("mx_records", {}) if isinstance(dns_info, dict) else {}
            mx_list = list(mx_recs.keys()) if isinstance(mx_recs, dict) else mx_recs if isinstance(mx_recs, list) else []
            
            # Also check from direct mx_records in summary
            if not mx_list:
                mx_data = summary.get("mx_records", {})
                if mx_data and isinstance(mx_data, dict):
                    mx_list = mx_data.get("records", [])
            
            provider = "Unknown"
            for mx in mx_list:
                mx_lower = str(mx).lower()
                if "google" in mx_lower or "gmail" in mx_lower:
                    provider = "Google Workspace"
                    break
                elif "outlook" in mx_lower or "microsoft" in mx_lower:
                    provider = "Microsoft 365"
                    break
                elif "zoho" in mx_lower:
                    provider = "Zoho Mail"
                    break
                elif "protonmail" in mx_lower:
                    provider = "ProtonMail"
                    break
                elif "mimecast" in mx_lower:
                    provider = "Mimecast"
                    break
                elif "amazonses" in mx_lower or "aws" in mx_lower:
                    provider = "Amazon SES"
                    break
                elif "yahoo" in mx_lower:
                    provider = "Yahoo Mail"
                    break
            st.markdown(f"`{provider}`")
        
        # Profiles if found
        profiles = summary.get("profiles", [])
        if profiles:
            st.markdown("**Profiles Found:**")
            st.markdown(", ".join([f"`{p}`" for p in profiles[:5]]))
    
    else:  # unknown type
        st.markdown("*See details below*")
    
    # Threat Scores for all types
    if summary["threat_scores"]:
        st.markdown("---")
        st.markdown("**Threat Scores**")
        sorted_scores = sorted(summary["threat_scores"], key=lambda x: x["score"], reverse=True)
        cols = st.columns(min(len(sorted_scores), 6))
        for col, item in zip(cols, sorted_scores[:6]):
            score = item["score"]
            color = "red" if score >= 70 else "orange" if score >= 40 else "green"
            col.markdown(f"**{item['source'][:10]}**: :{color}[{score}]")








def quick_analyze(value: str, data_type: str) -> Dict:
    """Quick analysis of any data type"""
    api_keys = get_api_keys()
    results = {}
    
    source_map = {
        "ip": IP_SOURCES,
        "domain": DOMAIN_SOURCES,
        "hash": HASH_SOURCES,
        "url": URL_SOURCES,
    }
    
    sources = source_map.get(data_type, [])[:3]  # Use top 3 sources for quick analysis
    
    for source_cls in sources:
        key = api_keys.get(source_cls.__name__, api_keys.get(source_cls.name, ""))
        try:
            source = source_cls(api_key=key)
            if source.requires_api_key and not source.is_available():
                continue
            result = source.lookup(value)
            results[source.name] = result
        except:
            pass
    
    return results


def render_related_data(related: Dict[str, List[Dict]], primary_value: str):
    """Render related data WITH inline auto-analysis"""
    has_related = any(len(v) > 0 for v in related.values())
    
    if not has_related:
        return
    
    st.markdown("---")
    st.markdown("## Related Data - Auto Analyzed")
    
    # === DOMAINS with DNS/SPF/DMARC analysis ===
    if related["domains"]:
        st.markdown(f"### Domains ({len(related['domains'])})")
        
        for item in related["domains"][:5]:
            domain = item["value"]
            if domain == primary_value:
                continue
            
            with st.expander(f"**{domain}** - from {item['source']}", expanded=True):
                with st.spinner("Analyzing..."):
                    domain_results = quick_analyze(domain, "domain")
                
                if domain_results:
                    # Show DNS info
                    col1, col2 = st.columns(2)
                    
                    for src_name, src_result in domain_results.items():
                        details = src_result.get("details", {})
                        
                        if "a_records" in details or "mx_records" in details:
                            with col1:
                                st.markdown("**DNS:**")
                                a_rec = details.get("a_records", [])
                                mx_rec = details.get("mx_records", [])
                                ns_rec = details.get("ns_records", [])
                                st.markdown(f"- A: {', '.join(a_rec[:3]) if a_rec else 'None'}")
                                st.markdown(f"- MX: {', '.join(mx_rec[:2]) if mx_rec else 'None'}")
                                st.markdown(f"- NS: {', '.join(ns_rec[:2]) if ns_rec else 'None'}")
                            
                            with col2:
                                st.markdown("**Mail Security:**")
                                has_spf = details.get("has_spf", False)
                                has_dmarc = details.get("has_dmarc", False)
                                has_dkim = details.get("has_dkim", False)
                                spf_text = details.get("spf_record", "")
                                dmarc_text = details.get("dmarc_record", "")
                                
                                # Determine DMARC policy
                                dmarc_policy = "none"
                                if isinstance(dmarc_text, str) and dmarc_text:
                                    if "p=reject" in dmarc_text:
                                        dmarc_policy = "reject"
                                    elif "p=quarantine" in dmarc_text:
                                        dmarc_policy = "quarantine"
                                
                                # Determine overall security
                                if dmarc_policy == "reject" and has_dkim:
                                    st.markdown("- :green[Strong]")
                                elif has_spf and has_dmarc:
                                    st.markdown("- :orange[Moderate]")
                                elif has_spf or has_dmarc:
                                    st.markdown("- :orange[Basic]")
                                else:
                                    st.markdown("- :red[Weak]")
                                
                                if has_dmarc:
                                    color = "green" if dmarc_policy == "reject" else "orange" if dmarc_policy == "quarantine" else "red"
                                    st.markdown(f"- DMARC: :{color}[{dmarc_policy.upper()}]")
                                else:
                                    st.markdown("- DMARC: :red[None]")
                        
                        if "registrar" in details:
                            st.markdown("**WHOIS:**")
                            st.markdown(f"- Registrar: {details.get('registrar', 'N/A')}")
                            st.markdown(f"- Created: {details.get('creation_date', 'N/A')}")
                        
                        if src_result.get("score") is not None:
                            score = src_result["score"]
                            color = "red" if score >= 50 else "green"
                            st.markdown(f"**{src_name} Score:** :{color}[{score}]")
                else:
                    st.info("Could not analyze")
                
                if st.button("Full Analysis", key=f"full_d_{domain[:15]}"):
                    st.session_state.next_value = domain
                    st.session_state.next_type = "domain"
                    st.rerun()
    
    # === IPs with quick threat check ===
    if related["ips"]:
        unique_ips = [ip for ip in related["ips"] if ip["value"] != primary_value]
        if unique_ips:
            st.markdown(f"### IPs ({len(unique_ips)})")
            
            for item in unique_ips[:5]:
                ip = item["value"]
                
                with st.expander(f"**{ip}** - from {item['source']}", expanded=True):
                    with st.spinner("Checking..."):
                        ip_results = quick_analyze(ip, "ip")
                    
                    if ip_results:
                        cols = st.columns(4)
                        
                        # Aggregate data
                        countries = []
                        threat_scores = []
                        flags = []
                        
                        for src_name, src_result in ip_results.items():
                            details = src_result.get("details", {})
                            score = src_result.get("score")
                            
                            country = details.get("country") or details.get("country_code")
                            if country:
                                countries.append(normalize_country(country))
                            
                            if score and score > 0:
                                threat_scores.append(f"{src_name[:6]}:{score}")
                            
                            if details.get("is_proxy") or details.get("proxy"):
                                flags.append("Proxy")
                            if details.get("is_vpn") or details.get("vpn"):
                                flags.append("VPN")
                            if details.get("is_tor"):
                                flags.append("TOR")
                        
                        cols[0].markdown(f"**Location:** {countries[0] if countries else 'Unknown'}")
                        cols[1].markdown(f"**Scores:** {', '.join(threat_scores) if threat_scores else 'Clean'}")
                        cols[2].markdown(f"**Flags:** {', '.join(set(flags)) if flags else 'None'}")
                        
                        if cols[3].button("Full", key=f"full_i_{ip}"):
                            st.session_state.next_value = ip
                            st.session_state.next_type = "ip"
                            st.rerun()
                    else:
                        st.info("Could not analyze")
    
    # === URLs with domain extraction ===
    if related.get("urls"):
        st.markdown(f"### URLs ({len(related['urls'])})")
        
        for item in related["urls"][:5]:
            url = item["value"]
            
            # Extract domain from URL
            domain_match = re.search(r'https?://([^/]+)', url)
            domain = domain_match.group(1) if domain_match else None
            
            with st.expander(f"**{url[:60]}{'...' if len(url)>60 else ''}**", expanded=False):
                st.code(url)
                st.caption(f"Source: {item['source']} ({item['reason']})")
                
                if domain:
                    st.markdown(f"**Domain:** `{domain}`")
                    with st.spinner("Checking domain..."):
                        domain_results = quick_analyze(domain, "domain")
                    
                    if domain_results:
                        for src_name, src_result in domain_results.items():
                            score = src_result.get("score")
                            if score is not None:
                                color = "red" if score >= 50 else "green"
                                st.markdown(f"**{src_name}:** :{color}[{score}]")
                
                col1, col2 = st.columns(2)
                if col1.button("Analyze URL", key=f"u_{hash(url)}"):
                    st.session_state.next_value = url
                    st.session_state.next_type = "url"
                    st.rerun()
                if domain and col2.button("Analyze Domain", key=f"ud_{domain[:10]}"):
                    st.session_state.next_value = domain
                    st.session_state.next_type = "domain"
                    st.rerun()
    
    # === Hashes ===
    if related["hashes"]:
        st.markdown(f"### Hashes ({len(related['hashes'])})")
        for item in related["hashes"][:5]:
            col1, col2, col3 = st.columns([4, 1, 1])
            col1.code(item["value"])
            col2.caption(item["reason"])
            if col3.button("Analyze", key=f"h_{item['value'][:8]}"):
                st.session_state.next_value = item["value"]
                st.session_state.next_type = "hash"
                st.rerun()
    
    # === Files ===
    if related.get("files"):
        with st.expander(f"Filenames ({len(related['files'])})", expanded=False):
            for item in related["files"][:8]:
                st.markdown(f"- `{item['value']}` - {item['source']}")




def render_source_details(source_name: str, result: dict, expanded: bool = True):
    """Render source details"""
    score = result.get("score")
    raw_value = result.get("raw_value", "N/A")
    details = result.get("details", {})
    error = result.get("error")
    
    if error:
        status = "[ERR]"
    elif score is None and raw_value in ["Not Found", "N/A", "Error", "Unknown", "No API Key", "No PTR Record", "Limited Access", "Clean", "Not in NSRL"]:
        status = "[--]"
    else:
        status = "[OK]"
    
    score_text = ""
    if score is not None:
        color = "red" if score >= 70 else "orange" if score >= 40 else "green"
        score_text = f":{color}[{score}/100]"
    
    with st.expander(f"{status} **{source_name}** - {raw_value} {score_text}", expanded=expanded):
        if error:
            st.error(f"Error: {error}")
            return
        
        if not details:
            st.info("No additional details")
            return
        
        for key, value in details.items():
            formatted = format_value(value)
            if formatted:
                if len(str(formatted)) > 150:
                    with st.expander(f"{key.replace('_', ' ').title()}"):
                        st.text(formatted)
                else:
                    st.markdown(f"**{key.replace('_', ' ').title()}:** {formatted}")
        
        with st.expander("Raw JSON"):
            st.json(result)


def lookup_all_sources(value: str, data_type: str) -> Dict[str, Dict]:
    """Lookup across all relevant sources"""
    api_keys = get_api_keys()
    
    source_map = {
        "ip": IP_SOURCES,
        "hash": HASH_SOURCES,
        "url": URL_SOURCES,
        "domain": DOMAIN_SOURCES,
        "email": EMAIL_SOURCES,
    }
    
    sources_list = source_map.get(data_type, [])
    if not sources_list:
        return {}
    
    lookup_value = value
    
    results = {}
    
    for source_cls in sources_list:
        key = api_keys.get(source_cls.__name__, api_keys.get(source_cls.name, ""))
        source = source_cls(api_key=key)
        
        if source.requires_api_key and not source.is_available():
            results[source.name] = {
                "score": None,
                "raw_value": "No API Key",
                "details": {},
                "error": "API key not configured"
            }
            continue
        
        try:
            result = source.lookup(lookup_value)
            results[source.name] = result
        except Exception as e:
            results[source.name] = {
                "score": None,
                "raw_value": "Error",
                "details": {},
                "error": str(e)
            }
    
    return results


# Initialize session state
if "next_value" not in st.session_state:
    st.session_state.next_value = None
if "next_type" not in st.session_state:
    st.session_state.next_type = None

# Main UI
st.markdown('<h1 class="main-header">beta-AIO</h1>', unsafe_allow_html=True)
st.markdown("*Enter data to lookup: IP, domain, hash, URL, email*")

col1, col2, col3 = st.columns([4, 1, 1])

default_value = st.session_state.next_value if st.session_state.next_value else ""
default_type = st.session_state.next_type if st.session_state.next_type else "Auto"

with col1:
    input_data = st.text_input("Enter data", value=default_value, placeholder="IP, Domain, Hash, URL, or Email", label_visibility="collapsed")

with col2:
    type_options = ["Auto", "IP", "Domain", "Hash", "URL", "Email"]
    default_idx = type_options.index(default_type.title()) if default_type and default_type.title() in type_options else 0
    type_override = st.selectbox("Type", type_options, index=default_idx, label_visibility="collapsed")

with col3:
    analyze_btn = st.button("Analyze", type="primary", use_container_width=True)

# Clear pivot state
if st.session_state.next_value:
    st.session_state.next_value = None
    st.session_state.next_type = None

if analyze_btn and input_data:
    cleaned = refang(input_data)
    
    if type_override == "Auto":
        data_type = classify_data(cleaned)
    else:
        data_type = type_override.lower()
    
    if data_type == "unknown":
        st.error("Could not determine data type. Please select manually.")
    else:
        st.markdown("---")
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Input", cleaned[:50] + "..." if len(cleaned) > 50 else cleaned)
        col2.metric("Type", data_type.upper())
        
        source_map = {"ip": IP_SOURCES, "hash": HASH_SOURCES, "url": URL_SOURCES, "domain": DOMAIN_SOURCES, "email": EMAIL_SOURCES}
        sources_count = len(source_map.get(data_type, []))
        col3.metric("Sources", sources_count)
        
        st.markdown("---")
        
        with st.spinner("Analyzing..."):
            results = lookup_all_sources(cleaned, data_type)
        
        # For DOMAIN type: If input is subdomain, also analyze main domain
        main_domain_for_domain = None
        main_domain_results = None
        main_domain_summary = None
        if data_type == "domain":
            main_domain_for_domain = extract_main_domain(cleaned)
            if main_domain_for_domain != cleaned.lower():
                # Input is a subdomain, analyze main domain first
                with st.spinner(f"Analyzing main domain: {main_domain_for_domain}..."):
                    main_domain_results = lookup_all_sources(main_domain_for_domain, "domain")
                main_domain_summary = build_summary(main_domain_results, "domain")
        
        # Summary
        summary = build_summary(results, data_type)
        
        # For URL analysis, run domain analysis
        domain_from_url = None
        domain_results = None
        domain_summary = None
        if data_type == "url":
            from urllib.parse import urlparse
            try:
                parsed = urlparse(cleaned)
                if parsed.netloc:
                    domain_from_url = parsed.netloc.lower()
                    with st.spinner(f"Analyzing domain: {domain_from_url}..."):
                        domain_results = lookup_all_sources(domain_from_url, "domain")
                    domain_summary = build_summary(domain_results, "domain")
            except Exception as e:
                st.warning(f"Could not analyze domain: {e}")
        
        # For email analysis, run domain analysis BEFORE rendering so we can merge DNS/DMARC data
        domain_from_email = None
        main_domain = None
        email_domain_results = None
        email_domain_summary = None
        subdomain_results = None
        subdomain_summary = None
        if data_type == "email" and "@" in cleaned:
            try:
                domain_from_email = cleaned.split("@")[1].lower()
                main_domain = extract_main_domain(domain_from_email)
                
                # Run domain analysis on main domain for proper SPF/DMARC/MX
                with st.spinner(f"Analyzing main domain: {main_domain}..."):
                    email_domain_results = lookup_all_sources(main_domain, "domain")
                email_domain_summary = build_summary(email_domain_results, "domain")
                
                # If subdomain is different, also analyze it
                if domain_from_email != main_domain:
                    with st.spinner(f"Analyzing subdomain: {domain_from_email}..."):
                        subdomain_results = lookup_all_sources(domain_from_email, "domain")
                    subdomain_summary = build_summary(subdomain_results, "domain")
                
                # Merge domain data into email summary for display
                # KEY: Use the ACTUAL email domain's data for mail security
                # If email is on a subdomain (temp.global.ntt), that's where mail goes
                # So we show subdomain's SPF/DMARC/DKIM, not the main domain's
                
                # Pick the right source: subdomain if available, else main domain
                mail_source = subdomain_summary if subdomain_summary else email_domain_summary
                
                if mail_source:
                    # Copy DNS records from the email's actual domain
                    if "dns_records" in mail_source:
                        summary["dns_records"] = mail_source["dns_records"]
                    # Copy SPF
                    if "spf_record" in mail_source:
                        summary["spf_record"] = mail_source["spf_record"]
                    # Copy DMARC
                    if "dmarc_record" in mail_source:
                        summary["dmarc_record"] = mail_source["dmarc_record"]
                    # Copy DKIM
                    if "dkim_record" in mail_source:
                        summary["dkim_record"] = mail_source["dkim_record"]
                    # Copy email security flags (SPF/DMARC/DKIM detection)
                    if "email_security" in mail_source:
                        summary["email_security"] = mail_source["email_security"]
                    # Copy MX records for mail provider detection
                    if "mx_records" in mail_source:
                        summary["mx_records"] = mail_source["mx_records"]
                
                # Subdomains ALWAYS come from main domain (CrtSh scans the registered domain)
                if email_domain_summary and "subdomains" in email_domain_summary:
                    summary["subdomains"] = email_domain_summary["subdomains"]
            except Exception as e:
                st.warning(f"Could not analyze email domain: {e}")
        
        # Now render the summary (with merged domain data for email)
        render_summary(summary, data_type)
        
        # Show main domain summary in expander for subdomain domain analysis
        if main_domain_summary:
            st.markdown("---")
            with st.expander(f"**Main Domain Analysis: {main_domain_for_domain}**", expanded=True):
                render_summary(main_domain_summary, "domain")
        
        # Show URL domain summary in expander
        if domain_summary:
            st.markdown("---")
            with st.expander(f"**Domain Analysis: {domain_from_url}**", expanded=True):
                render_summary(domain_summary, "domain")
        
        # Show full domain summary in expander for email (main domain)
        if email_domain_summary:
            st.markdown("---")
            with st.expander(f"**Main Domain Analysis: {main_domain}**", expanded=True):
                render_summary(email_domain_summary, "domain")
        
        # Also show subdomain analysis for email if different from main
        if subdomain_summary:
            st.markdown("---")
            with st.expander(f"**Subdomain Analysis: {domain_from_email}**", expanded=False):
                render_summary(subdomain_summary, "domain")
        
        
        # Related data
        related = extract_related_data(results)
        
        # Add domain results to related data extraction (for URL)
        if domain_results:
            domain_related = extract_related_data(domain_results)
            # Merge the related data
            for key in related:
                existing = {item["value"].lower() for item in related[key]}
                for item in domain_related.get(key, []):
                    if item["value"].lower() not in existing:
                        related[key].append(item)
        
        # Add email domain results to related data (for email)
        if email_domain_results:
            email_domain_related = extract_related_data(email_domain_results)
            for key in related:
                existing = {item["value"].lower() for item in related[key]}
                for item in email_domain_related.get(key, []):
                    if item["value"].lower() not in existing:
                        related[key].append(item)
        
        # For URL analysis, also add the URL's own domain to related domains
        if data_type == "url" and domain_from_url:
            # Add to related domains if not already there
            existing_domains = {d["value"] for d in related["domains"]}
            if domain_from_url not in existing_domains:
                related["domains"].insert(0, {"value": domain_from_url, "source": "URL", "reason": "url_domain"})
        
        # For email analysis, add the email's domain to related domains
        if data_type == "email" and domain_from_email:
            existing_domains = {d["value"] for d in related["domains"]}
            if domain_from_email not in existing_domains:
                related["domains"].insert(0, {"value": domain_from_email, "source": "Email", "reason": "email_domain"})
        
        render_related_data(related, cleaned)
        
        st.markdown("---")
        
        # Detailed results
        st.markdown("## Source Details")
        
        found_results = {k: v for k, v in results.items() 
                        if v.get("score") is not None or 
                        v.get("raw_value") not in ["Not Found", "N/A", "Error", "No API Key", "No PTR Record", "Limited Access", "Clean", "Not in NSRL"]}
        not_found_results = {k: v for k, v in results.items() if k not in found_results}
        
        st.markdown(f"**Found data in {len(found_results)}/{len(results)} sources**")
        
        for source_name, result in found_results.items():
            render_source_details(source_name, result, expanded=True)
        
        if not_found_results:
            with st.expander(f"Empty sources ({len(not_found_results)})", expanded=False):
                for source_name, result in not_found_results.items():
                    st.markdown(f"- **{source_name}**: {result.get('raw_value', 'N/A')}")

st.markdown("---")
st.markdown("""
<style>
    .footer {
        position: fixed;
        bottom: 0;
        left: 0;
        width: 100%;
        text-align: center;
        padding: 10px;
        background-color: #0E1117;
        color: #fff;
        font-size: 14px;
    }
</style>
<div class="footer">
    ᚱᛟᛟᛏ@ᛞᛖᛖ:~#
</div>
""", unsafe_allow_html=True)
