"""
Domain OSINT Sources - Comprehensive
WHOIS, DNS records, reputation, subdomains
"""
from typing import Dict, Any, List
import socket
from .base import BaseSource


class WHOISLookup(BaseSource):
    """WHOIS lookup via RDAP"""
    name = "WHOIS"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        rdap_urls = [
            f"https://rdap.verisign.com/com/v1/domain/{domain}",
            f"https://rdap.org/domain/{domain}",
        ]
        
        data = None
        for url in rdap_urls:
            data = self._request("GET", url)
            if data:
                break
        
        if not data:
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        registrar = None
        creation_date = None
        expiration_date = None
        nameservers = []
        registrant = {}
        
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [[],[]])[1]
                for item in vcard:
                    if item[0] == "fn":
                        registrar = item[3]
                        break
            if "registrant" in roles:
                vcard = entity.get("vcardArray", [[],[]])[1]
                for item in vcard:
                    if item[0] == "fn":
                        registrant["name"] = item[3]
                    if item[0] == "org":
                        registrant["org"] = item[3]
        
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                creation_date = event.get("eventDate", "")[:10]
            if event.get("eventAction") == "expiration":
                expiration_date = event.get("eventDate", "")[:10]
        
        for ns in data.get("nameservers", []):
            if ns.get("ldhName"):
                nameservers.append(ns.get("ldhName"))
        
        return {
            "score": None,
            "raw_value": f"Registrar: {registrar}" if registrar else "Found",
            "details": {
                "domain": data.get("ldhName"),
                "status": data.get("status", []),
                "registrar": registrar,
                "creation_date": creation_date,
                "expiration_date": expiration_date,
                "nameservers": nameservers,
                "registrant_name": registrant.get("name"),
                "registrant_org": registrant.get("org"),
            }
        }


class DNSLookup(BaseSource):
    """DNS records lookup (A, MX, NS, TXT, SPF, DMARC)"""
    name = "DNS_Records"
    requires_api_key = False
    rate_limit_delay = 0.5
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        results = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
        }
        
        # A Records
        try:
            a_records = socket.getaddrinfo(domain, None, socket.AF_INET)
            results["a_records"] = list(set([r[4][0] for r in a_records]))
        except:
            pass
        
        doh_url = "https://dns.google/resolve"
        
        # MX Records
        mx_data = self._request("GET", doh_url, params={"name": domain, "type": "MX"})
        if mx_data and mx_data.get("Answer"):
            results["mx_records"] = [a.get("data", "").rstrip(".") for a in mx_data["Answer"]]
        
        # NS Records
        ns_data = self._request("GET", doh_url, params={"name": domain, "type": "NS"})
        if ns_data and ns_data.get("Answer"):
            results["ns_records"] = [a.get("data", "").rstrip(".") for a in ns_data["Answer"]]
        
        # TXT Records
        txt_data = self._request("GET", doh_url, params={"name": domain, "type": "TXT"})
        if txt_data and txt_data.get("Answer"):
            results["txt_records"] = [a.get("data", "").strip('"') for a in txt_data["Answer"]][:5]
        
        # SPF Check
        spf_record = None
        has_spf = False
        for txt in results["txt_records"]:
            if "v=spf1" in txt:
                has_spf = True
                spf_record = txt
                break
        
        # DMARC Check
        has_dmarc = False
        dmarc_record = None
        dmarc_data = self._request("GET", doh_url, params={"name": f"_dmarc.{domain}", "type": "TXT"})
        if dmarc_data and dmarc_data.get("Answer"):
            has_dmarc = True
            dmarc_record = dmarc_data["Answer"][0].get("data", "").strip('"')
        
        # DKIM Check (common selectors)
        has_dkim = False
        for selector in ["default", "google", "selector1", "selector2"]:
            dkim_data = self._request("GET", doh_url, params={"name": f"{selector}._domainkey.{domain}", "type": "TXT"})
            if dkim_data and dkim_data.get("Answer"):
                has_dkim = True
                break
        
        return {
            "score": None,
            "raw_value": f"A:{len(results['a_records'])}, MX:{len(results['mx_records'])}",
            "details": {
                "a_records": results["a_records"],
                "mx_records": results["mx_records"],
                "ns_records": results["ns_records"],
                "txt_records": results["txt_records"],
                "has_spf": has_spf,
                "spf_record": spf_record,
                "has_dmarc": has_dmarc,
                "dmarc_record": dmarc_record,
                "has_dkim": has_dkim,
            }
        }


class VirusTotalDomain(BaseSource):
    """VirusTotal Domain lookup"""
    name = "VirusTotal"
    requires_api_key = True
    rate_limit_delay = 15.0
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
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
        
        return {
            "score": score,
            "raw_value": f"{malicious}/{total} detections",
            "details": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": stats.get("harmless", 0),
                "reputation": attrs.get("reputation", 0),
                "registrar": attrs.get("registrar"),
                "creation_date": attrs.get("creation_date"),
                "categories": attrs.get("categories", {}),
                "popularity_ranks": attrs.get("popularity_ranks", {}),
            }
        }


class AlienVaultDomain(BaseSource):
    """AlienVault OTX for domains"""
    name = "AlienVault_OTX"
    requires_api_key = True
    rate_limit_delay = 1.0
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        
        data = self._request("GET", url, headers=headers)
        
        if not data:
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])
        
        if pulse_count > 10:
            score = 80
        elif pulse_count > 5:
            score = 60
        elif pulse_count > 0:
            score = 40
        else:
            score = 0
        
        return {
            "score": score if pulse_count > 0 else None,
            "raw_value": f"Pulses: {pulse_count}",
            "details": {
                "pulse_count": pulse_count,
                "pulse_names": [p.get("name") for p in pulses[:5]],
                "alexa": data.get("alexa"),
            }
        }


class ThreatCrowd(BaseSource):
    """ThreatCrowd - Open threat intelligence"""
    name = "ThreatCrowd"
    requires_api_key = False
    rate_limit_delay = 10.0
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/"
        params = {"domain": domain}
        
        data = self._request("GET", url, params=params)
        
        if not data or data.get("response_code") != "1":
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        resolutions = data.get("resolutions", [])
        subdomains = data.get("subdomains", [])
        emails = data.get("emails", [])
        hashes = data.get("hashes", [])
        
        votes = data.get("votes", 0)
        if votes < 0:
            score = 70
        elif votes > 0:
            score = 20
        else:
            score = None
        
        return {
            "score": score,
            "raw_value": f"IPs:{len(resolutions)}, Subs:{len(subdomains)}",
            "details": {
                "resolutions": resolutions[:10],
                "subdomains": subdomains[:10],
                "emails": emails,
                "hashes": hashes[:5],
                "votes": votes,
            }
        }


class URLhausDomain(BaseSource):
    """URLhaus - Check if domain hosts malware"""
    name = "URLhaus"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        api_url = "https://urlhaus-api.abuse.ch/v1/host/"
        
        try:
            response = self.session.post(api_url, data={"host": domain}, timeout=10)
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if data.get("query_status") != "ok":
            return {"score": 0, "raw_value": "Clean", "details": {}}
        
        url_count = data.get("url_count", 0)
        urls = data.get("urls", [])
        
        online = sum(1 for u in urls if u.get("url_status") == "online")
        
        return {
            "score": 100 if online > 0 else 70,
            "raw_value": f"MALWARE: {url_count} URLs ({online} online)",
            "details": {
                "url_count": url_count,
                "online_count": online,
                "first_seen": data.get("firstseen"),
                "urls": [u.get("url") for u in urls[:5]],
                "tags": list(set([t for u in urls for t in u.get("tags", [])])),
            }
        }


class Pulsedive(BaseSource):
    """Pulsedive - Threat intelligence"""
    name = "Pulsedive"
    requires_api_key = False
    rate_limit_delay = 2.0
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        url = f"https://pulsedive.com/api/explore.php"
        params = {"q": f"ioc={domain}", "limit": 1, "pretty": 1}
        
        data = self._request("GET", url, params=params)
        
        if not data or not data.get("results"):
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        result = data["results"][0]
        risk = result.get("risk", "unknown")
        
        risk_score = {"critical": 95, "high": 75, "medium": 50, "low": 25, "none": 0}.get(risk, None)
        
        return {
            "score": risk_score,
            "raw_value": f"Risk: {risk.upper()}",
            "details": {
                "risk": risk,
                "stamp_seen": result.get("stamp_seen"),
                "threats": result.get("threats", []),
            }
        }


class ThreatMinerDomain(BaseSource):
    """ThreatMiner for domains"""
    name = "ThreatMiner"
    requires_api_key = False
    rate_limit_delay = 6.0
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        # Get passive DNS (rt=1)
        url = f"https://api.threatminer.org/v2/domain.php"
        params = {"q": domain, "rt": "1"}
        
        data = self._request("GET", url, params=params)
        
        if not data or data.get("status_code") != "200":
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        results = data.get("results", [])
        
        # Get subdomains (rt=4)
        sub_data = self._request("GET", url, params={"q": domain, "rt": "4"})
        subdomains = sub_data.get("results", []) if sub_data else []
        
        # Get related samples (rt=5)
        sample_data = self._request("GET", url, params={"q": domain, "rt": "5"})
        samples = sample_data.get("results", []) if sample_data else []
        
        return {
            "score": 60 if samples else None,
            "raw_value": f"IPs:{len(results)}, Samples:{len(samples)}",
            "details": {
                "passive_dns": results[:10],
                "subdomains": subdomains[:10],
                "samples": samples[:5],
            }
        }


class CrtSh(BaseSource):
    """Certificate Transparency Logs"""
    name = "CertTransparency"
    requires_api_key = False
    rate_limit_delay = 2.0
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            response = self.session.get(url, timeout=30)
            if response.status_code != 200:
                return {"score": None, "raw_value": f"HTTP {response.status_code}", "details": {}}
            data = response.json()
        except Exception as e:
            return {"score": None, "raw_value": f"Error: {type(e).__name__}", "details": {}}
        
        if not data:
            return {"score": None, "raw_value": "No Certs", "details": {}}
        
        # Extract unique subdomains
        subdomains = set()
        for cert in data[:50]:
            name_value = cert.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*"):
                    subdomains.add(name)
        
        return {
            "score": None,
            "raw_value": f"{len(subdomains)} subdomains from certs",
            "details": {
                "subdomain_count": len(subdomains),
                "subdomains": list(subdomains)[:50],
                "cert_count": len(data),
            }
        }


class WebArchive(BaseSource):
    """Check domain history via Wayback Machine"""
    name = "WebArchive"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        url = f"https://archive.org/wayback/available?url={domain}"
        
        data = self._request("GET", url)
        
        if not data:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        snapshot = data.get("archived_snapshots", {}).get("closest")
        
        if not snapshot:
            return {"score": None, "raw_value": "Not Archived", "details": {}}
        
        return {
            "score": None,
            "raw_value": f"First seen: {snapshot.get('timestamp', '')[:8]}",
            "details": {
                "timestamp": snapshot.get("timestamp"),
                "archive_url": snapshot.get("url"),
            }
        }



class GoogleSafeBrowsingDomain(BaseSource):
    """Google Safe Browsing API for domains"""
    name = "GoogleSB"
    requires_api_key = True
    rate_limit_delay = 0.5
    
    def lookup(self, domain: str) -> Dict[str, Any]:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        
        # Check both http and https versions
        urls = [f"http://{domain}/", f"https://{domain}/"]
        
        payload = {
            "client": {"clientId": "osint-aio", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls]
            }
        }
        
        try:
            response = self.session.post(api_url, json=payload, timeout=10)
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        matches = data.get("matches", [])
        
        if not matches:
            return {"score": 0, "raw_value": "Safe", "details": {"safe": True}}
        
        threat_types = list(set([m.get("threatType") for m in matches]))
        
        return {
            "score": 100,
            "raw_value": f"UNSAFE: {', '.join(threat_types)}",
            "details": {
                "threat_types": threat_types,
                "phishing": "SOCIAL_ENGINEERING" in threat_types,
                "malware": "MALWARE" in threat_types,
            }
        }


# All domain sources
DOMAIN_SOURCES = [
    WHOISLookup,
    DNSLookup,
    VirusTotalDomain,
    AlienVaultDomain,
    URLhausDomain,
    Pulsedive,
    ThreatCrowd,
    ThreatMinerDomain,
    CrtSh,
    WebArchive,
    GoogleSafeBrowsingDomain,
]
