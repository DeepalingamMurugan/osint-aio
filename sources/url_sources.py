"""
URL OSINT Sources - Comprehensive
"""
from typing import Dict, Any
from urllib.parse import urlparse
from .base import BaseSource


class URLhaus(BaseSource):
    """URLhaus by abuse.ch"""
    name = "URLhaus"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, url: str) -> Dict[str, Any]:
        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        
        try:
            response = self.session.post(api_url, data={"url": url}, timeout=10)
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if data.get("query_status") != "ok":
            return {"score": 0, "raw_value": "Clean", "details": {}}
        
        threat = data.get("threat", "malware")
        url_status = data.get("url_status", "")
        tags = data.get("tags", [])
        payloads = data.get("payloads", [])
        
        score = 100 if url_status == "online" else 70
        
        return {
            "score": score,
            "raw_value": f"MALWARE: {threat} ({url_status})",
            "details": {
                "threat": threat,
                "status": url_status,
                "date_added": data.get("date_added"),
                "tags": tags,
                "payloads_count": len(payloads),
                "host": data.get("host"),
            }
        }


class VirusTotalURL(BaseSource):
    """VirusTotal URL lookup"""
    name = "VirusTotal"
    requires_api_key = True
    rate_limit_delay = 15.0
    
    def lookup(self, url: str) -> Dict[str, Any]:
        import base64
        
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": self.api_key}
        
        data = self._request("GET", api_url, headers=headers)
        
        if not data or "data" not in data:
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        attrs = data["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 1
        
        score = int(((malicious + suspicious * 0.5) / max(total, 1)) * 100)
        
        return {
            "score": score,
            "raw_value": f"{malicious}/{total} detections",
            "details": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": stats.get("harmless", 0),
                "categories": attrs.get("categories", {}),
                "final_url": attrs.get("last_final_url"),
                "title": attrs.get("title"),
                "outgoing_links": len(attrs.get("outgoing_links", [])),
            }
        }


class OpenPhish(BaseSource):
    """OpenPhish - Free phishing feed"""
    name = "OpenPhish"
    requires_api_key = False
    rate_limit_delay = 1.0
    _phishing_urls = None
    _last_fetch = None
    
    def lookup(self, url: str) -> Dict[str, Any]:
        import time
        
        # Fetch/cache feed
        if not OpenPhish._phishing_urls or not OpenPhish._last_fetch or (time.time() - OpenPhish._last_fetch) > 3600:
            try:
                response = self.session.get("https://openphish.com/feed.txt", timeout=30)
                if response.status_code == 200:
                    OpenPhish._phishing_urls = set(response.text.strip().split('\n'))
                    OpenPhish._last_fetch = time.time()
            except:
                pass
        
        if not OpenPhish._phishing_urls:
            return {"score": None, "raw_value": "Feed Error", "details": {}}
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        if url in OpenPhish._phishing_urls:
            return {"score": 100, "raw_value": "PHISHING - Exact Match", "details": {"match_type": "exact"}}
        
        for phish_url in OpenPhish._phishing_urls:
            if domain in phish_url:
                return {"score": 80, "raw_value": "PHISHING - Domain Match", "details": {"match_type": "domain"}}
        
        return {"score": 0, "raw_value": "Clean", "details": {}}


class URLScan(BaseSource):
    """URLscan.io"""
    name = "URLScan"
    requires_api_key = True
    rate_limit_delay = 2.0
    
    def lookup(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        domain = parsed.netloc or url
        
        api_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1"
        headers = {"API-Key": self.api_key}
        
        data = self._request("GET", api_url, headers=headers)
        
        if not data or not data.get("results"):
            return {"score": None, "raw_value": "Not Scanned", "details": {}}
        
        result = data["results"][0]
        verdicts = result.get("verdicts", {}).get("overall", {})
        
        malicious = verdicts.get("malicious", False)
        score_val = verdicts.get("score", 0)
        
        return {
            "score": max(score_val, 80) if malicious else min(score_val, 30),
            "raw_value": f"{'MALICIOUS' if malicious else 'Clean'} (score:{score_val})",
            "details": {
                "page_domain": result.get("page", {}).get("domain"),
                "page_ip": result.get("page", {}).get("ip"),
                "page_country": result.get("page", {}).get("country"),
                "page_server": result.get("page", {}).get("server"),
                "task_time": result.get("task", {}).get("time"),
            }
        }


class PhishTank(BaseSource):
    """PhishTank - Free phishing database"""
    name = "PhishTank"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, url: str) -> Dict[str, Any]:
        import hashlib
        
        # PhishTank wants URL as MD5 hash
        url_hash = hashlib.md5(url.encode()).hexdigest()
        
        api_url = f"https://checkurl.phishtank.com/checkurl/index.php"
        
        try:
            response = self.session.post(api_url, 
                data={"url": url, "format": "json"},
                timeout=10)
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        results = data.get("results", {})
        in_database = results.get("in_database", False)
        valid = results.get("valid", False)
        
        if in_database and valid:
            return {
                "score": 100,
                "raw_value": "PHISHING - Verified",
                "details": {
                    "phish_id": results.get("phish_id"),
                    "verified": results.get("verified"),
                    "verified_at": results.get("verified_at"),
                }
            }
        
        return {"score": 0, "raw_value": "Clean", "details": {}}


class ThreatFoxURL(BaseSource):
    """ThreatFox by abuse.ch"""
    name = "ThreatFox"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, url: str) -> Dict[str, Any]:
        api_url = "https://threatfox-api.abuse.ch/api/v1/"
        
        # Extract domain/IP from URL
        parsed = urlparse(url)
        ioc = parsed.netloc or url
        
        try:
            response = self.session.post(api_url, 
                json={"query": "search_ioc", "search_term": ioc},
                timeout=10)
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if data.get("query_status") != "ok" or not data.get("data"):
            return {"score": 0, "raw_value": "Clean", "details": {}}
        
        result = data["data"][0]
        malware = result.get("malware_printable", "Unknown")
        
        return {
            "score": 95,
            "raw_value": f"IOC: {malware}",
            "details": {
                "malware": malware,
                "threat_type": result.get("threat_type"),
                "confidence": result.get("confidence_level"),
                "first_seen": result.get("first_seen"),
                "ioc_type": result.get("ioc_type"),
            }
        }


class WaybackMachine(BaseSource):
    """Wayback Machine - Check URL history"""
    name = "Wayback"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, url: str) -> Dict[str, Any]:
        api_url = f"https://archive.org/wayback/available?url={url}"
        
        data = self._request("GET", api_url)
        
        if not data:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        snapshot = data.get("archived_snapshots", {}).get("closest")
        
        if not snapshot:
            return {"score": None, "raw_value": "Not Archived", "details": {}}
        
        return {
            "score": None,
            "raw_value": f"Archived: {snapshot.get('timestamp', '')[:8]}",
            "details": {
                "timestamp": snapshot.get("timestamp"),
                "archive_url": snapshot.get("url"),
                "status": snapshot.get("status"),
            }
        }


class CheckShortURL(BaseSource):
    """Check where short URLs redirect"""
    name = "ShortURL_Check"
    requires_api_key = False
    rate_limit_delay = 0.5
    
    def lookup(self, url: str) -> Dict[str, Any]:
        # Only process known short URL domains
        short_domains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly", "rebrand.ly"]
        
        parsed = urlparse(url)
        if parsed.netloc not in short_domains:
            return {"score": None, "raw_value": "Not Short URL", "details": {}}
        
        try:
            response = self.session.head(url, allow_redirects=True, timeout=10)
            final_url = response.url
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if final_url != url:
            return {
                "score": None,
                "raw_value": f"Redirects to: {urlparse(final_url).netloc}",
                "details": {
                    "final_url": final_url,
                    "final_domain": urlparse(final_url).netloc,
                    "redirects": len(response.history),
                }
            }
        
        return {"score": None, "raw_value": "No Redirect", "details": {}}


class IPQS_URL(BaseSource):
    """IPQualityScore URL Check"""
    name = "IPQS"
    requires_api_key = True
    rate_limit_delay = 1.0
    
    def lookup(self, url: str) -> Dict[str, Any]:
        import urllib.parse
        encoded_url = urllib.parse.quote(url, safe='')
        api_url = f"https://ipqualityscore.com/api/json/url/{self.api_key}/{encoded_url}"
        
        data = self._request("GET", api_url)
        
        if not data or not data.get("success"):
            return {"score": None, "raw_value": "Error", "details": {}}
        
        risk_score = data.get("risk_score", 0)
        
        flags = []
        if data.get("phishing"):
            flags.append("Phishing")
        if data.get("malware"):
            flags.append("Malware")
        if data.get("suspicious"):
            flags.append("Suspicious")
        if data.get("spamming"):
            flags.append("Spam")
        
        return {
            "score": risk_score,
            "raw_value": ", ".join(flags) if flags else f"Risk: {risk_score}",
            "details": {
                "risk_score": risk_score,
                "phishing": data.get("phishing"),
                "malware": data.get("malware"),
                "suspicious": data.get("suspicious"),
                "adult": data.get("adult"),
                "category": data.get("category"),
                "domain": data.get("domain"),
                "ip_address": data.get("ip_address"),
                "country_code": data.get("country_code"),
            }
        }


class GoogleSafeBrowsing(BaseSource):
    """Google Safe Browsing API"""
    name = "GoogleSB"
    requires_api_key = True
    rate_limit_delay = 0.5
    
    def lookup(self, url: str) -> Dict[str, Any]:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        
        payload = {
            "client": {"clientId": "osint-aio", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        try:
            response = self.session.post(api_url, json=payload, timeout=10)
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        matches = data.get("matches", [])
        
        if not matches:
            return {"score": 0, "raw_value": "Clean", "details": {"safe": True}}
        
        threat_types = [m.get("threatType") for m in matches]
        threat_type = threat_types[0] if threat_types else "Unknown"
        
        return {
            "score": 100,
            "raw_value": f"UNSAFE: {threat_type}",
            "details": {
                "threat_types": threat_types,
                "threat_type": threat_type,
                "platform_types": [m.get("platformType") for m in matches],
                "cache_duration": matches[0].get("cacheDuration") if matches else None,
            }
        }


class HybridAnalysisURL(BaseSource):
    """Hybrid Analysis URL Scanner - submits URL for analysis"""
    name = "HybridAnalysis"
    requires_api_key = True
    rate_limit_delay = 3.0
    
    def lookup(self, url: str) -> Dict[str, Any]:
        # Search for existing URL analysis
        search_url = "https://www.hybrid-analysis.com/api/v2/search/terms"
        headers = {
            "api-key": self.api_key,
            "User-Agent": "Falcon Sandbox",
            "accept": "application/json"
        }
        
        try:
            response = self.session.post(
                search_url,
                headers=headers,
                data={"url": url},
                timeout=15
            )
            
            if response.status_code == 401:
                return {"score": None, "raw_value": "Auth Error", "details": {}}
            if response.status_code == 429:
                return {"score": None, "raw_value": "Rate Limited", "details": {}}
            
            data = response.json()
        except Exception as e:
            return {"score": None, "raw_value": f"Error: {str(e)[:15]}", "details": {}}
        
        if not data.get("result"):
            return {"score": None, "raw_value": "Not Analyzed", "details": {"sandbox_link": f"https://www.hybrid-analysis.com/submit/url?url={url}"}}
        
        result = data["result"][0] if isinstance(data["result"], list) else data["result"]
        
        verdict = result.get("verdict")
        threat_score = result.get("threat_score", 0)
        vx_family = result.get("vx_family")
        
        score = threat_score if threat_score else (90 if verdict == "malicious" else 50 if verdict == "suspicious" else 0)
        
        return {
            "score": score,
            "raw_value": f"{verdict or 'Unknown'} ({threat_score})" if threat_score else verdict or "Clean",
            "details": {
                "verdict": verdict,
                "threat_score": threat_score,
                "vx_family": vx_family,
                "environment": result.get("environment_description"),
                "submit_name": result.get("submit_name"),
                "analysis_start_time": result.get("analysis_start_time"),
                "job_id": result.get("job_id"),
                "sandbox_link": f"https://www.hybrid-analysis.com/sample/{result.get('sha256')}" if result.get("sha256") else None,
            }
        }


# All URL sources
URL_SOURCES = [
    URLhaus,
    VirusTotalURL,
    ThreatFoxURL,
    OpenPhish,
    PhishTank,
    URLScan,
    IPQS_URL,
    GoogleSafeBrowsing,
    HybridAnalysisURL,
    WaybackMachine,
    CheckShortURL,
]
