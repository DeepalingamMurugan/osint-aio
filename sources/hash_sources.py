"""
Hash (File) OSINT Sources - Comprehensive with Full Data
"""
from typing import Dict, Any
from .base import BaseSource


class VirusTotalHash(BaseSource):
    """VirusTotal Hash lookup - Most comprehensive"""
    name = "VirusTotal"
    requires_api_key = True
    rate_limit_delay = 15.0
    
    def lookup(self, hash_value: str) -> Dict[str, Any]:
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        headers = {"x-apikey": self.api_key}
        
        data = self._request("GET", url, headers=headers)
        
        if not data or "data" not in data:
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        attrs = data["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1
        
        score = int(((malicious + suspicious * 0.5) / max(total, 1)) * 100)
        
        # Get threat classification
        threat_classification = attrs.get("popular_threat_classification", {})
        threat_label = threat_classification.get("suggested_threat_label", "")
        threat_category = ""
        if threat_classification.get("popular_threat_category"):
            cats = threat_classification["popular_threat_category"]
            if isinstance(cats, list) and cats:
                threat_category = cats[0].get("value", "")
        
        # Get sandbox verdicts
        sandbox_verdicts = attrs.get("sandbox_verdicts", {})
        sandbox_results = []
        for sandbox_name, verdict in sandbox_verdicts.items():
            sandbox_results.append({
                "sandbox": sandbox_name,
                "category": verdict.get("category"),
                "malware_names": verdict.get("malware_names", [])
            })
        
        # CVE extraction from threat names
        cves = []
        for name in attrs.get("names", []):
            if "CVE-" in name.upper():
                import re
                found = re.findall(r'CVE-\d{4}-\d+', name.upper())
                cves.extend(found)
        
        # Type detection
        type_desc = attrs.get("type_description", "Unknown")
        type_extension = attrs.get("type_extension", "")
        magic = attrs.get("magic", "")
        
        # PE Info - Signature, Copyright, Product, etc.
        pe_info = attrs.get("pe_info", {})
        signature_info = attrs.get("signature_info", {})
        
        # Extract file metadata
        product = signature_info.get("product") or pe_info.get("product", "")
        company = signature_info.get("copyright") or pe_info.get("company", "")
        description = signature_info.get("description") or pe_info.get("file_description", "")
        file_version = signature_info.get("file version") or pe_info.get("product_version", "")
        original_name = signature_info.get("original name") or pe_info.get("original_filename", "")
        
        # Signing info
        signing_date = signature_info.get("signing date", "")
        signers = signature_info.get("signers", "")
        verified = signature_info.get("verified", "")
        
        # Also check authentihash and other signing details
        authentihash = attrs.get("authentihash", "")
        
        return {
            "score": score,
            "raw_value": f"{malicious}/{total} detections - {threat_label}" if threat_label else f"{malicious}/{total} detections",
            "details": {
                "hash_type": f"SHA256 ({len(hash_value)} chars)" if len(hash_value) == 64 else f"MD5 ({len(hash_value)} chars)" if len(hash_value) == 32 else f"SHA1 ({len(hash_value)} chars)",
                "file_type": type_desc,
                "file_extension": type_extension,
                "magic": magic,
                "size": attrs.get("size"),
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": stats.get("harmless", 0),
                "threat_label": threat_label,
                "threat_category": threat_category,
                "cves": list(set(cves)),
                "filenames": attrs.get("names", [])[:10],
                "tags": attrs.get("tags", []),
                "md5": attrs.get("md5"),
                "sha1": attrs.get("sha1"),
                "sha256": attrs.get("sha256"),
                "ssdeep": attrs.get("ssdeep"),
                "first_seen": attrs.get("first_submission_date"),
                "last_seen": attrs.get("last_analysis_date"),
                "sandbox_verdicts": sandbox_results[:5],
                "reputation": attrs.get("reputation"),
                # PE/Signature Info
                "product": product,
                "company": company,
                "copyright": company,  # Often same as company
                "description": description,
                "file_version": file_version,
                "original_name": original_name,
                "signing_date": signing_date,
                "signers": signers,
                "signature_verified": verified,
                "authentihash": authentihash,
            }
        }


class MalwareBazaar(BaseSource):
    """MalwareBazaar - abuse.ch (requires API key)"""
    name = "MalwareBazaar"
    requires_api_key = True
    rate_limit_delay = 1.0
    
    def lookup(self, hash_value: str) -> Dict[str, Any]:
        url = "https://mb-api.abuse.ch/api/v1/"
        
        # MalwareBazaar requires Auth-Key header
        headers = {}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        
        try:
            response = self.session.post(url, 
                data={"query": "get_info", "hash": hash_value},
                headers=headers,
                timeout=15)
            data = response.json()
        except Exception as e:
            return {"score": None, "raw_value": f"Error: {str(e)[:30]}", "details": {}}
        
        if data.get("query_status") == "no_results":
            return {"score": 0, "raw_value": "Not Found", "details": {}}
        
        if data.get("query_status") != "ok" or not data.get("data"):
            error = data.get("query_status", "Unknown error")
            return {"score": None, "raw_value": f"API Error: {error}", "details": {}}
        
        info = data["data"][0]
        
        signature = info.get("signature") or "Unknown"
        file_type = info.get("file_type", "unknown")
        tags = info.get("tags", [])
        
        # Extract all sandbox data
        vendor_intel = info.get("vendor_intel", {})
        
        # Helper to safely get nested data (vendor_intel values can be list or dict)
        def get_vendor_data(vendor_name, field):
            data = vendor_intel.get(vendor_name)
            if not data:
                return None
            if isinstance(data, list) and len(data) > 0:
                return data[0].get(field) if isinstance(data[0], dict) else None
            if isinstance(data, dict):
                return data.get(field)
            return None
        
        # AnyRun data
        anyrun_verdict = get_vendor_data("ANY.RUN", "verdict")
        anyrun_analysis = get_vendor_data("ANY.RUN", "analysis_url")
        
        # Cape data
        cape_verdict = get_vendor_data("CAPE", "verdict")
        
        # VMRay data
        vmray_verdict = get_vendor_data("VMRay", "verdict")
        
        # Extract ALL sandbox links from vendor_intel
        sandbox_links = {}
        link_fields = {
            "ANY.RUN": "analysis_url",
            "CAPE": "sample", 
            "Triage": "link",
            "FileScan-IO": "report",
            "UnpacMe": "link",
            "VMRay": "sample_url",
            "YOROI_YOMI": "link",
            "Intezer": "analysis_url",
            "DocGuard": "link",
            "vxCube": "report",
            "Kaspersky": "permalink",
            "ReversingLabs": "scanner_match",
        }
        
        for vendor, link_field in link_fields.items():
            vendor_data = vendor_intel.get(vendor)
            if vendor_data:
                # Handle list or dict
                if isinstance(vendor_data, list) and vendor_data:
                    link = vendor_data[0].get(link_field) if isinstance(vendor_data[0], dict) else None
                elif isinstance(vendor_data, dict):
                    link = vendor_data.get(link_field)
                else:
                    link = None
                if link:
                    sandbox_links[vendor] = link
        
        # YARA rules
        yara_rules = [y.get("rule_name") for y in info.get("yara_rules", []) if isinstance(y, dict)]
        
        # ClamAV
        intelligence = info.get("intelligence", {})
        if isinstance(intelligence, dict):
            clamav = intelligence.get("clamav", [])
        else:
            clamav = []
        
        # C2 servers (ole_information can be list or dict)
        c2_servers = []
        ole_info = info.get("ole_information", {})
        if isinstance(ole_info, dict):
            for c2 in ole_info.get("c2_servers", []):
                c2_servers.append(c2)
        
        # Determine hash type from the hash we looked up
        hash_type = "SHA256" if len(hash_value) == 64 else "MD5" if len(hash_value) == 32 else "SHA1" if len(hash_value) == 40 else "Unknown"
        
        return {
            "score": 100,
            "raw_value": f"MALWARE: {signature} ({file_type})",
            "details": {
                "hash_type": f"{hash_type} ({len(hash_value)} chars)",
                "signature": signature,
                "file_type": file_type,
                "file_type_mime": info.get("file_type_mime"),
                "file_size": info.get("file_size"),
                "first_seen": info.get("first_seen"),
                "last_seen": info.get("last_seen"),
                "filename": info.get("file_name"),
                "filenames": [info.get("file_name")] if info.get("file_name") else [],
                "tags": tags,
                "origin_country": info.get("origin_country"),
                "delivery_method": info.get("delivery_method"),
                "yara_rules": yara_rules,
                "clamav_results": clamav,
                "anyrun_verdict": anyrun_verdict,
                "anyrun_link": anyrun_analysis,
                "cape_verdict": cape_verdict,
                "vmray_verdict": vmray_verdict,
                "vendor_intel": list(vendor_intel.keys()),
                "sandbox_links": sandbox_links,
                "c2_servers": c2_servers,
                "downloads": intelligence.get("downloads") if isinstance(intelligence, dict) else None,
                "uploads": intelligence.get("uploads") if isinstance(intelligence, dict) else None,
            }
        }


class ThreatFoxHash(BaseSource):
    """ThreatFox - abuse.ch IOC database"""
    name = "ThreatFox"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, hash_value: str) -> Dict[str, Any]:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        
        try:
            response = self.session.post(url, 
                json={"query": "search_hash", "hash": hash_value},
                timeout=10)
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if data.get("query_status") not in ["ok"] or not data.get("data"):
            return {"score": 0, "raw_value": "Clean", "details": {}}
        
        info = data["data"][0]
        malware = info.get("malware_printable", "Unknown")
        
        return {
            "score": 95,
            "raw_value": f"IOC: {malware}",
            "details": {
                "malware": malware,
                "malware_alias": info.get("malware_alias"),
                "threat_type": info.get("threat_type"),
                "confidence": info.get("confidence_level"),
                "ioc": info.get("ioc"),
                "ioc_type": info.get("ioc_type"),
                "first_seen": info.get("first_seen"),
                "tags": info.get("tags", []),
            }
        }


class URLhausPayload(BaseSource):
    """URLhaus Payload lookup - abuse.ch"""
    name = "URLhaus"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, hash_value: str) -> Dict[str, Any]:
        url = "https://urlhaus-api.abuse.ch/v1/payload/"
        
        if len(hash_value) == 32:
            payload = {"md5_hash": hash_value}
        elif len(hash_value) == 64:
            payload = {"sha256_hash": hash_value}
        else:
            return {"score": None, "raw_value": "Invalid Hash", "details": {}}
        
        try:
            response = self.session.post(url, data=payload, timeout=10)
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if data.get("query_status") != "ok":
            return {"score": 0, "raw_value": "Clean", "details": {}}
        
        file_type = data.get("file_type", "Unknown")
        signature = data.get("signature", "Malware")
        urls = data.get("urls", [])
        
        return {
            "score": 100,
            "raw_value": f"{signature} ({file_type})",
            "details": {
                "file_type": file_type,
                "signature": signature,
                "urls_count": data.get("url_count", 0),
                "first_seen": data.get("firstseen"),
                "last_seen": data.get("lastseen"),
                "distribution_urls": [u.get("url") for u in urls[:10]],
            }
        }


class OTXHash(BaseSource):
    """AlienVault OTX"""
    name = "AlienVault_OTX"
    requires_api_key = True
    rate_limit_delay = 1.0
    
    def lookup(self, hash_value: str) -> Dict[str, Any]:
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        
        data = self._request("GET", url, headers=headers)
        
        if not data or "error" in str(data).lower():
            return {"score": 0, "raw_value": "Not Found", "details": {}}
        
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])
        
        if pulse_count == 0:
            score = 0
        elif pulse_count < 5:
            score = 40
        else:
            score = min(90, 40 + pulse_count * 5)
        
        # Extract malware names from pulses
        malware_names = []
        for p in pulses[:10]:
            if p.get("name"):
                malware_names.append(p["name"])
        
        return {
            "score": score if pulse_count > 0 else None,
            "raw_value": f"Pulses: {pulse_count}",
            "details": {
                "pulse_count": pulse_count,
                "pulse_names": malware_names[:5],
                "type_title": data.get("type_title"),
            }
        }


class CIRCLHashlookup(BaseSource):
    """CIRCL Hashlookup - Known-good files (NSRL)"""
    name = "CIRCL_Hashlookup"
    requires_api_key = False
    rate_limit_delay = 0.5
    
    def lookup(self, hash_value: str) -> Dict[str, Any]:
        if len(hash_value) == 32:
            endpoint = "md5"
        elif len(hash_value) == 40:
            endpoint = "sha1"
        elif len(hash_value) == 64:
            endpoint = "sha256"
        else:
            return {"score": None, "raw_value": "Invalid", "details": {}}
        
        url = f"https://hashlookup.circl.lu/lookup/{endpoint}/{hash_value}"
        data = self._request("GET", url)
        
        if not data:
            return {"score": None, "raw_value": "Not in NSRL", "details": {}}
        
        filename = data.get("FileName", "Known File")
        
        return {
            "score": 0,
            "raw_value": f"SAFE: {filename[:30]}",
            "details": {
                "filename": filename,
                "product": data.get("ProductName"),
                "os": data.get("OpSystemCode"),
                "known_source": "NSRL",
            }
        }


class ThreatMinerHash(BaseSource):
    """ThreatMiner for hashes"""
    name = "ThreatMiner"
    requires_api_key = False
    rate_limit_delay = 6.0
    
    def lookup(self, hash_value: str) -> Dict[str, Any]:
        url = f"https://api.threatminer.org/v2/sample.php"
        
        data = self._request("GET", url, params={"q": hash_value, "rt": "1"})
        
        if not data or data.get("status_code") != "200":
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        results = data.get("results", [])
        if not results:
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        result = results[0]
        
        # Get HTTP traffic
        http_data = self._request("GET", url, params={"q": hash_value, "rt": "6"})
        http_traffic = http_data.get("results", []) if http_data else []
        
        # Get domains
        host_data = self._request("GET", url, params={"q": hash_value, "rt": "7"})
        hosts = host_data.get("results", []) if host_data else []
        
        return {
            "score": 70,
            "raw_value": f"Found: {result.get('file_type', 'Unknown')}",
            "details": {
                "file_name": result.get("file_name"),
                "file_type": result.get("file_type"),
                "architecture": result.get("architecture"),
                "http_traffic": http_traffic[:5],
                "domains": hosts[:10],
            }
        }


class HybridAnalysis(BaseSource):
    """Hybrid Analysis - Free sandbox using overview endpoint"""
    name = "HybridAnalysis"
    requires_api_key = True
    rate_limit_delay = 5.0
    
    def lookup(self, hash_value: str) -> Dict[str, Any]:
        # Use /overview endpoint which works (not /search/hash which returns 400)
        url = f"https://www.hybrid-analysis.com/api/v2/overview/{hash_value}"
        headers = {
            "api-key": self.api_key,
            "User-Agent": "Falcon Sandbox",
            "accept": "application/json"
        }
        
        try:
            response = self.session.get(url, headers=headers, timeout=15)
            
            if response.status_code == 401:
                return {"score": None, "raw_value": "Auth Error", "details": {}}
            if response.status_code == 404:
                return {"score": None, "raw_value": "Not Found", "details": {}}
            if response.status_code != 200:
                return {"score": None, "raw_value": f"HTTP {response.status_code}", "details": {}}
            
            data = response.json()
        except Exception as e:
            return {"score": None, "raw_value": f"Error: {str(e)[:20]}", "details": {}}
        
        if not data:
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        # Extract threat score and verdict from tags
        threat_score = data.get("threat_score", 0) or 0
        tags = data.get("tags", [])
        
        # Determine verdict from tags
        verdict = "unknown"
        if "malicious" in tags:
            verdict = "malicious"
        elif "suspicious" in tags:
            verdict = "suspicious"
        elif "clean" in tags or "whitelisted" in tags:
            verdict = "clean"
        
        score = threat_score
        if verdict == "malicious":
            score = max(score, 80)
        elif verdict == "suspicious":
            score = max(score, 50)
        
        # Get scanner results
        scanners = data.get("scanners", [])
        scanner_results = {}
        for s in scanners:
            if s.get("status") and s.get("status") != "no-result":
                scanner_results[s.get("name", "Unknown")] = s.get("status")
        
        # Get type info
        type_short = data.get("type_short", [])
        file_type = type_short[0] if type_short else data.get("type", "unknown")
        
        return {
            "score": score,
            "raw_value": f"{verdict.upper()}: {file_type} (Score: {threat_score})",
            "details": {
                "verdict": verdict,
                "threat_score": threat_score,
                "vx_family": data.get("vx_family"),
                "file_type": file_type,
                "file_name": data.get("file_name"),
                "filenames": [data.get("file_name")] if data.get("file_name") else [],
                "tags": tags,
                "submitted_at": data.get("submitted_at"),
                "analysis_start": data.get("analysis_start_time"),
                "scanner_results": scanner_results,
                "multiscan_result": data.get("multiscan_result"),
            }
        }


class JoeSandbox(BaseSource):
    """Joe Sandbox Cloud - Free tier public reports"""
    name = "JoeSandbox"
    requires_api_key = False
    rate_limit_delay = 2.0
    
    def lookup(self, hash_value: str) -> Dict[str, Any]:
        # Joe Sandbox public search
        url = f"https://jbxcloud.joesecurity.org/api/v2/analysis/search"
        
        try:
            response = self.session.post(url, data={"q": hash_value}, timeout=10)
            if response.status_code != 200:
                return {"score": None, "raw_value": "API Error", "details": {}}
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if not data or not data.get("data"):
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        analyses = data.get("data", [])
        if not analyses:
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        result = analyses[0]
        detection = result.get("detection", "unknown")
        
        score = 90 if detection == "malicious" else 50 if detection == "suspicious" else 0
        
        return {
            "score": score if detection in ["malicious", "suspicious"] else None,
            "raw_value": f"{detection.upper()}",
            "details": {
                "detection": detection,
                "webid": result.get("webid"),
                "analysis_url": f"https://jbxcloud.joesecurity.org/analysis/{result.get('webid')}" if result.get("webid") else None,
            }
        }


# All Hash sources
HASH_SOURCES = [
    VirusTotalHash,
    MalwareBazaar,
    ThreatFoxHash,
    URLhausPayload,
    OTXHash,
    HybridAnalysis,
    ThreatMinerHash,
    JoeSandbox,
    CIRCLHashlookup,
]
