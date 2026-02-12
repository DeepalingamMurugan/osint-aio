"""
IP Address OSINT Sources - Full Details Version
Returns ALL available data from each source
"""
from typing import Dict, Any, Optional
from .base import BaseSource


class ShodanInternetDB(BaseSource):
    """Shodan InternetDB - Ports, vulns, CPE, hostnames, tags"""
    name = "Shodan_InternetDB"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = f"https://internetdb.shodan.io/{ip}"
        data = self._request("GET", url)
        
        if not data:
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        vulns = data.get("vulns", [])
        ports = data.get("ports", [])
        hostnames = data.get("hostnames", [])
        cpes = data.get("cpes", [])
        tags = data.get("tags", [])
        
        score = 0
        if vulns:
            score = min(100, len(vulns) * 20)
        elif len(ports) > 10:
            score = 30
        
        return {
            "score": score,
            "raw_value": f"Ports:{len(ports)}, Vulns:{len(vulns)}",
            "details": {
                "ports": ports,
                "vulns": vulns,
                "hostnames": hostnames,
                "cpes": cpes,
                "tags": tags
            }
        }


class AbuseIPDB(BaseSource):
    """AbuseIPDB - Abuse reports, ISP, location, usage type"""
    name = "AbuseIPDB"
    requires_api_key = True
    rate_limit_delay = 1.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 365, "verbose": ""}
        
        data = self._request("GET", url, headers=headers, params=params)
        
        if not data or "data" not in data:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        info = data["data"]
        confidence = info.get("abuseConfidenceScore", 0)
        reports = info.get("totalReports", 0)
        
        return {
            "score": confidence,
            "raw_value": f"Abuse:{confidence}%, Reports:{reports}",
            "details": {
                "abuse_confidence": confidence,
                "total_reports": reports,
                "distinct_users": info.get("numDistinctUsers", 0),
                "last_reported": info.get("lastReportedAt"),
                "is_public": info.get("isPublic"),
                "is_whitelisted": info.get("isWhitelisted"),
                "isp": info.get("isp"),
                "domain": info.get("domain"),
                "usage_type": info.get("usageType"),
                "country_code": info.get("countryCode"),
                "country_name": info.get("countryName"),
                "hostnames": info.get("hostnames", [])
            }
        }


class VirusTotalIP(BaseSource):
    """VirusTotal - Detections, AS info, reputation, WHOIS"""
    name = "VirusTotal"
    requires_api_key = True
    rate_limit_delay = 15.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.api_key}
        
        data = self._request("GET", url, headers=headers)
        
        if not data or "data" not in data:
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        attrs = data["data"].get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = sum(stats.values()) if stats else 1
        
        score = int(((malicious + suspicious * 0.5) / max(total, 1)) * 100)
        
        return {
            "score": score,
            "raw_value": f"Mal:{malicious}, Sus:{suspicious}/{total}",
            "details": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "reputation": attrs.get("reputation", 0),
                "as_owner": attrs.get("as_owner"),
                "asn": attrs.get("asn"),
                "network": attrs.get("network"),
                "country": attrs.get("country"),
                "continent": attrs.get("continent"),
                "whois": attrs.get("whois", "")[:500],
                "whois_date": attrs.get("whois_date"),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "tags": attrs.get("tags", [])
            }
        }


class BlocklistDE(BaseSource):
    """Blocklist.de - Attack counts from honeypots"""
    name = "Blocklist_DE"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = f"http://api.blocklist.de/api.php?ip={ip}&start=1"
        
        try:
            response = self.session.get(url, timeout=10)
            text = response.text.strip()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if not text or "attacks" not in text:
            return {"score": 0, "raw_value": "Clean", "details": {"attacks": 0, "reports": 0}}
        
        attacks = 0
        reports = 0
        
        for part in text.replace("<br />", "\n").split("\n"):
            if "attacks:" in part:
                try:
                    attacks = int(part.split(":")[1].strip())
                except:
                    pass
            if "reports:" in part:
                try:
                    reports = int(part.split(":")[1].strip())
                except:
                    pass
        
        if attacks > 100:
            score = 80
        elif attacks > 50:
            score = 60
        elif attacks > 10:
            score = 40
        elif attacks > 0:
            score = 20
        else:
            score = 0
        
        return {
            "score": score,
            "raw_value": f"Attacks:{attacks}, Reports:{reports}",
            "details": {
                "attacks": attacks,
                "reports": reports
            }
        }


class ProxyCheck(BaseSource):
    """ProxyCheck.io - VPN/Proxy detection, risk score, geolocation"""
    name = "ProxyCheck"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1&risk=1&port=1&seen=1&days=7&tag=msg"
        data = self._request("GET", url)
        
        if not data or data.get("status") != "ok":
            return {"score": None, "raw_value": "Error", "details": {}}
        
        info = data.get(ip, {})
        
        is_proxy = info.get("proxy") == "yes"
        is_vpn = info.get("vpn") == "yes"
        risk = info.get("risk", 0)
        
        flags = []
        if is_proxy:
            flags.append("Proxy")
        if is_vpn:
            flags.append("VPN")
        if info.get("type"):
            flags.append(info.get("type"))
        
        provider = info.get("provider", info.get("organisation", "Unknown"))
        
        raw_value = provider[:30]
        if flags:
            raw_value += f" [{','.join(flags)}]"
        if risk:
            raw_value += f" Risk:{risk}"
        
        return {
            "score": None,
            "raw_value": raw_value,
            "details": {
                "is_proxy": is_proxy,
                "is_vpn": is_vpn,
                "proxy_type": info.get("type"),
                "risk_score": risk,
                "provider": info.get("provider"),
                "organisation": info.get("organisation"),
                "asn": info.get("asn"),
                "isocode": info.get("isocode"),
                "country": info.get("country"),
                "region": info.get("region"),
                "city": info.get("city"),
                "latitude": info.get("latitude"),
                "longitude": info.get("longitude"),
                "port": info.get("port"),
                "last_seen": info.get("seen"),
                "operator": info.get("operator", {})
            }
        }


class FeodoTracker(BaseSource):
    """Feodo Tracker - C2 botnet IP blocklist"""
    name = "FeodoTracker"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
        data = self._request("GET", url)
        
        if not data:
            return {"score": None, "raw_value": "N/A", "details": {}}
        
        for entry in data:
            if entry.get("ip_address") == ip:
                malware = entry.get("malware", "Unknown")
                return {
                    "score": 100,
                    "raw_value": f"C2: {malware}",
                    "details": {
                        "malware": malware,
                        "port": entry.get("port"),
                        "status": entry.get("status"),
                        "hostname": entry.get("hostname"),
                        "as_number": entry.get("as_number"),
                        "as_name": entry.get("as_name"),
                        "country": entry.get("country"),
                        "first_seen": entry.get("first_seen"),
                        "last_online": entry.get("last_online")
                    }
                }
        
        return {"score": 0, "raw_value": "Not in C2 list", "details": {}}


class IPAPIcom(BaseSource):
    """IP-API.com - Free geolocation"""
    name = "IP_Geolocation"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting"
        data = self._request("GET", url)
        
        if not data or data.get("status") != "success":
            return {"score": None, "raw_value": "Error", "details": {}}
        
        flags = []
        if data.get("proxy"):
            flags.append("Proxy")
        if data.get("hosting"):
            flags.append("Hosting")
        if data.get("mobile"):
            flags.append("Mobile")
        
        location = f"{data.get('city', '')}, {data.get('country', '')}"
        
        return {
            "score": None,
            "raw_value": f"{data.get('isp', 'Unknown')[:30]} - {location}",
            "details": {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "as_name": data.get("asname"),
                "is_mobile": data.get("mobile"),
                "is_proxy": data.get("proxy"),
                "is_hosting": data.get("hosting")
            }
        }


class GreyNoiseCommunity(BaseSource):
    """GreyNoise Community - Internet scanner/noise detection"""
    name = "GreyNoise"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {"Accept": "application/json"}
        
        data = self._request("GET", url, headers=headers)
        
        if not data:
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        classification = data.get("classification", "unknown")
        
        if classification == "malicious":
            score = 90
        elif classification == "benign":
            score = 0
        elif noise:
            score = 40
        else:
            score = None
        
        raw_parts = []
        if noise:
            raw_parts.append("NOISE")
        if riot:
            raw_parts.append("RIOT")
        if classification != "unknown":
            raw_parts.append(classification.upper())
        
        return {
            "score": score,
            "raw_value": ", ".join(raw_parts) if raw_parts else "Not Seen",
            "details": {
                "noise": noise,
                "riot": riot,
                "classification": classification,
                "name": data.get("name"),
                "link": data.get("link"),
                "last_seen": data.get("last_seen"),
                "message": data.get("message")
            }
        }


class BGPView(BaseSource):
    """BGPView - ASN and prefix information"""
    name = "BGPView"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = f"https://api.bgpview.io/ip/{ip}"
        data = self._request("GET", url)
        
        if not data or data.get("status") != "ok":
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        ip_data = data.get("data", {})
        prefixes = ip_data.get("prefixes", [])
        
        if not prefixes:
            return {"score": None, "raw_value": "No BGP Data", "details": {}}
        
        prefix = prefixes[0]
        asn_info = prefix.get("asn", {})
        
        return {
            "score": None,
            "raw_value": f"AS{asn_info.get('asn', 'N/A')} - {asn_info.get('name', 'Unknown')[:30]}",
            "details": {
                "prefix": prefix.get("prefix"),
                "ip": prefix.get("ip"),
                "cidr": prefix.get("cidr"),
                "asn": asn_info.get("asn"),
                "as_name": asn_info.get("name"),
                "as_description": asn_info.get("description"),
                "as_country": asn_info.get("country_code"),
                "rir_allocation_prefix": ip_data.get("rir_allocation", {}).get("prefix"),
                "rir_name": ip_data.get("rir_allocation", {}).get("rir_name"),
                "allocation_status": ip_data.get("rir_allocation", {}).get("allocation_status"),
                "date_allocated": ip_data.get("rir_allocation", {}).get("date_allocated"),
                "ptr_record": ip_data.get("ptr_record")
            }
        }


class IPQualityScore(BaseSource):
    """IPQualityScore - Fraud and risk scoring (free tier)"""
    name = "IPQualityScore"
    requires_api_key = False
    rate_limit_delay = 2.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        # Free endpoint without API key (limited info)
        url = f"https://www.ipqualityscore.com/api/json/ip/free/{ip}"
        data = self._request("GET", url)
        
        if not data or not data.get("success", True):
            return {"score": None, "raw_value": "Error", "details": {}}
        
        fraud_score = data.get("fraud_score", 0)
        
        flags = []
        if data.get("vpn"):
            flags.append("VPN")
        if data.get("tor"):
            flags.append("TOR")
        if data.get("proxy"):
            flags.append("Proxy")
        if data.get("bot_status"):
            flags.append("Bot")
        
        return {
            "score": fraud_score,
            "raw_value": f"Fraud:{fraud_score}" + (f" [{','.join(flags)}]" if flags else ""),
            "details": {
                "fraud_score": fraud_score,
                "is_vpn": data.get("vpn"),
                "is_tor": data.get("tor"),
                "is_proxy": data.get("proxy"),
                "is_crawler": data.get("is_crawler"),
                "is_bot": data.get("bot_status"),
                "recent_abuse": data.get("recent_abuse"),
                "country_code": data.get("country_code"),
                "city": data.get("city"),
                "region": data.get("region"),
                "isp": data.get("ISP"),
                "asn": data.get("ASN"),
                "organization": data.get("organization"),
                "timezone": data.get("timezone"),
                "mobile": data.get("mobile"),
                "host": data.get("host"),
                "abuse_velocity": data.get("abuse_velocity"),
                "connection_type": data.get("connection_type")
            }
        }


class ThreatMiner(BaseSource):
    """ThreatMiner - Threat intelligence (WHOIS, passive DNS, etc)"""
    name = "ThreatMiner"
    requires_api_key = False
    rate_limit_delay = 2.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        # rt=1 = WHOIS, rt=2 = passive DNS, rt=4 = related samples, rt=5 = SSL certs
        results = {}
        
        # Get WHOIS
        whois_url = f"https://api.threatminer.org/v2/host.php?q={ip}&rt=1"
        whois_data = self._request("GET", whois_url)
        
        # Get passive DNS
        dns_url = f"https://api.threatminer.org/v2/host.php?q={ip}&rt=2"
        dns_data = self._request("GET", dns_url)
        
        # Get related malware
        malware_url = f"https://api.threatminer.org/v2/host.php?q={ip}&rt=4"
        malware_data = self._request("GET", malware_url)
        
        whois_info = {}
        if whois_data and whois_data.get("status_code") == "200":
            whois_results = whois_data.get("results", [])
            if whois_results:
                whois_info = whois_results[0] if isinstance(whois_results[0], dict) else {}
        
        dns_records = []
        if dns_data and dns_data.get("status_code") == "200":
            dns_records = dns_data.get("results", [])[:20]
        
        malware_samples = []
        if malware_data and malware_data.get("status_code") == "200":
            malware_samples = malware_data.get("results", [])[:10]
        
        score = None
        if malware_samples:
            score = min(100, len(malware_samples) * 20)
        
        raw_value = ""
        if malware_samples:
            raw_value = f"Malware:{len(malware_samples)}"
        elif dns_records:
            raw_value = f"DNS:{len(dns_records)}"
        else:
            raw_value = "No threat data"
        
        return {
            "score": score,
            "raw_value": raw_value,
            "details": {
                "whois_org": whois_info.get("org_name"),
                "whois_registrar": whois_info.get("registrar"),
                "whois_creation": whois_info.get("create_date"),
                "whois_updated": whois_info.get("update_date"),
                "passive_dns_count": len(dns_records),
                "passive_dns_domains": [r.get("domain") for r in dns_records[:10] if isinstance(r, dict)] if dns_records else [],
                "malware_sample_count": len(malware_samples),
                "malware_samples": malware_samples[:5]
            }
        }


class CriminalIP(BaseSource):
    """Criminal IP - Web crawled threat data"""
    name = "CriminalIP"
    requires_api_key = False
    rate_limit_delay = 2.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        # Criminal IP public search info (web scraping approach)
        # Note: For full API access, requires API key
        # This uses the limited free information available
        
        url = f"https://api.criminalip.io/v1/asset/ip/summary?ip={ip}"
        headers = {"x-api-key": self.api_key or ""}
        
        data = self._request("GET", url, headers=headers)
        
        if not data or data.get("status") != 200:
            return {"score": None, "raw_value": "Limited Access", "details": {}}
        
        result = data.get("data", {})
        
        score_info = result.get("score", {})
        inbound = score_info.get("inbound", 0)
        outbound = score_info.get("outbound", 0)
        
        return {
            "score": max(inbound, outbound) if inbound or outbound else None,
            "raw_value": f"In:{inbound}, Out:{outbound}",
            "details": {
                "inbound_score": inbound,
                "outbound_score": outbound,
                "issues": result.get("issues", []),
                "current_opened_port_count": result.get("current_opened_port_count"),
                "ip_category": result.get("ip_category"),
                "is_vpn": result.get("is_vpn"),
                "is_proxy": result.get("is_proxy"),
                "is_tor": result.get("is_tor"),
                "is_hosting": result.get("is_hosting"),
                "is_mobile": result.get("is_mobile"),
                "is_scanner": result.get("is_scanner"),
                "is_snort": result.get("is_snort")
            }
        }


class AlienVaultOTX(BaseSource):
    """AlienVault OTX - Threat intelligence pulses"""
    name = "AlienVault_OTX"
    requires_api_key = True
    rate_limit_delay = 1.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        
        data = self._request("GET", url, headers=headers)
        
        if not data:
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        reputation = data.get("reputation", 0)
        
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
            "raw_value": f"Pulses:{pulse_count}",
            "details": {
                "pulse_count": pulse_count,
                "reputation": reputation,
                "asn": data.get("asn"),
                "country_code": data.get("country_code"),
                "country_name": data.get("country_name"),
                "city": data.get("city"),
                "region": data.get("region"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "indicator": data.get("indicator"),
                "whois": data.get("whois", "")[:300] if data.get("whois") else None
            }
        }


class IPinfo(BaseSource):
    """IPinfo.io - Geolocation and ASN (free tier)"""
    name = "IPinfo"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = f"https://ipinfo.io/{ip}/json"
        data = self._request("GET", url)
        
        if not data or data.get("error"):
            return {"score": None, "raw_value": "Error", "details": {}}
        
        org = data.get("org", "")
        city = data.get("city", "")
        country = data.get("country", "")
        
        return {
            "score": None,
            "raw_value": f"{city}, {country}" if city else country,
            "details": {
                "city": city,
                "region": data.get("region"),
                "country": country,
                "org": org,
                "asn": org.split(" ")[0] if org else None,
                "as_name": " ".join(org.split(" ")[1:]) if org else None,
                "hostname": data.get("hostname"),
                "timezone": data.get("timezone"),
                "postal": data.get("postal"),
                "loc": data.get("loc"),
            }
        }


class Pulsedive(BaseSource):
    """Pulsedive - Community threat intelligence (free)"""
    name = "Pulsedive"
    requires_api_key = False
    rate_limit_delay = 2.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = f"https://pulsedive.com/api/info.php"
        params = {"indicator": ip, "pretty": 1}
        
        data = self._request("GET", url, params=params)
        
        if not data or data.get("error"):
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        risk = data.get("risk", "unknown")
        risk_score = {"critical": 90, "high": 70, "medium": 50, "low": 20, "none": 0}.get(risk, None)
        
        return {
            "score": risk_score,
            "raw_value": f"Risk: {risk.upper()}",
            "details": {
                "risk": risk,
                "risk_recommended": data.get("risk_recommended"),
                "threats": [t.get("name") for t in data.get("threats", [])],
                "feeds": [f.get("name") for f in data.get("feeds", [])],
                "attributes": data.get("attributes", {}),
                "properties": data.get("properties", {}),
            }
        }


class URLhausIP(BaseSource):
    """URLhaus - Check if IP hosts malware URLs"""
    name = "URLhaus_IP"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        
        try:
            response = self.session.post(url, data={"host": ip}, timeout=10)
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if data.get("query_status") != "ok":
            return {"score": 0, "raw_value": "Clean", "details": {}}
        
        url_count = data.get("url_count", 0)
        urls = data.get("urls", [])
        
        if url_count > 10:
            score = 90
        elif url_count > 5:
            score = 70
        elif url_count > 0:
            score = 50
        else:
            score = 0
        
        return {
            "score": score,
            "raw_value": f"Malware URLs: {url_count}",
            "details": {
                "url_count": url_count,
                "first_seen": data.get("firstseen"),
                "blacklists": data.get("blacklists", {}),
                "urls": [{"url": u.get("url"), "status": u.get("url_status"), "threat": u.get("threat")} for u in urls[:5]],
            }
        }


class IPWHOIS(BaseSource):
    """IPWHOIS.io - Free IP geolocation and WHOIS"""
    name = "IPWHOIS"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        url = f"https://ipwhois.app/json/{ip}"
        data = self._request("GET", url)
        
        if not data or not data.get("success", True):
            return {"score": None, "raw_value": "Error", "details": {}}
        
        return {
            "score": None,
            "raw_value": f"{data.get('city', '')}, {data.get('country', '')}",
            "details": {
                "country": data.get("country"),
                "country_code": data.get("country_code"),
                "region": data.get("region"),
                "city": data.get("city"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("asn"),
                "as_name": data.get("as"),
                "timezone": data.get("timezone"),
                "timezone_name": data.get("timezone_name"),
            }
        }


class GoogleSafeBrowsingIP(BaseSource):
    """Google Safe Browsing API for IPs"""
    name = "GoogleSB"
    requires_api_key = True
    rate_limit_delay = 0.5
    
    def lookup(self, ip: str) -> Dict[str, Any]:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        
        # Check IP as URL
        urls = [f"http://{ip}/", f"https://{ip}/"]
        
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


# All available IP sources
IP_SOURCES = [
    AbuseIPDB,
    VirusTotalIP,
    GreyNoiseCommunity,
    ShodanInternetDB,
    BGPView,
    BlocklistDE,
    ProxyCheck,
    IPAPIcom,
    IPinfo,
    IPWHOIS,
    Pulsedive,
    URLhausIP,
    ThreatMiner,
    AlienVaultOTX,
    FeodoTracker,
    GoogleSafeBrowsingIP,
]

