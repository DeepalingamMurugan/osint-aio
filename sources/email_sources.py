"""
Email OSINT Sources
Analyze email addresses for reputation, breaches, domain info
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, Any
from .base import BaseSource
from constants import DISPOSABLE_DOMAINS, FREE_EMAIL_PROVIDERS


class EmailRepIO(BaseSource):
    """EmailRep.io - Email reputation and breach data (free)"""
    name = "EmailRep"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, email: str) -> Dict[str, Any]:
        url = f"https://emailrep.io/{email}"
        headers = {"User-Agent": "OSINT-AIO", "Accept": "application/json"}
        
        try:
            response = self.session.get(url, headers=headers, timeout=10)
            if response.status_code == 429:
                return {"score": None, "raw_value": "Rate Limited", "details": {}}
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if not data.get("email"):
            return {"score": None, "raw_value": "Not Found", "details": {}}
        
        reputation = data.get("reputation", "none")
        suspicious = data.get("suspicious", False)
        malicious_activity = data.get("details", {}).get("malicious_activity", False)
        
        # Calculate score
        score = 0
        if malicious_activity:
            score = 90
        elif suspicious:
            score = 60
        elif reputation == "low":
            score = 40
        elif reputation == "medium":
            score = 20
        
        details = data.get("details", {})
        
        return {
            "score": score,
            "raw_value": f"{reputation.title()} reputation" + (" - Suspicious" if suspicious else ""),
            "details": {
                "reputation": reputation,
                "suspicious": suspicious,
                "malicious_activity": malicious_activity,
                "credentials_leaked": details.get("credentials_leaked", False),
                "data_breach": details.get("data_breach", False),
                "domain_exists": details.get("domain_exists", True),
                "deliverable": details.get("deliverable", True),
                "free_provider": details.get("free_provider", False),
                "disposable": details.get("disposable", False),
                "spam": details.get("spam", False),
                "profiles": details.get("profiles", []),
                "blacklisted": details.get("blacklisted", False),
                "days_since_domain_creation": details.get("days_since_domain_creation"),
            }
        }


class HaveIBeenPwnedEmail(BaseSource):
    """Have I Been Pwned - Check for data breaches"""
    name = "HIBP"
    requires_api_key = True
    rate_limit_delay = 1.5
    
    def lookup(self, email: str) -> Dict[str, Any]:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": self.api_key,
            "User-Agent": "OSINT-AIO"
        }
        
        try:
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 404:
                return {"score": 0, "raw_value": "No Breaches", "details": {"breaches": []}}
            if response.status_code == 401:
                return {"score": None, "raw_value": "Invalid API Key", "details": {}}
            if response.status_code == 429:
                return {"score": None, "raw_value": "Rate Limited", "details": {}}
            
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if not data:
            return {"score": 0, "raw_value": "No Breaches", "details": {"breaches": []}}
        
        breach_count = len(data)
        breach_names = [b.get("Name") for b in data[:10]]
        
        # Score based on number of breaches
        score = min(100, breach_count * 15)
        
        return {
            "score": score,
            "raw_value": f"{breach_count} breaches found",
            "details": {
                "breach_count": breach_count,
                "breaches": breach_names,
                "breach_details": [
                    {
                        "name": b.get("Name"),
                        "date": b.get("BreachDate"),
                        "data_classes": b.get("DataClasses", [])
                    }
                    for b in data[:5]
                ]
            }
        }


class DisposableEmailCheck(BaseSource):
    """Check if email is disposable/temporary"""
    name = "DisposableCheck"
    requires_api_key = False
    rate_limit_delay = 0.5
    
    # Using DISPOSABLE_DOMAINS from constants.py
    
    def lookup(self, email: str) -> Dict[str, Any]:
        if "@" not in email:
            return {"score": None, "raw_value": "Invalid Email", "details": {}}
        
        domain = email.split("@")[1].lower()
        
        is_disposable = domain in DISPOSABLE_DOMAINS
        
        if is_disposable:
            return {
                "score": 70,
                "raw_value": "Disposable Email",
                "details": {
                    "disposable": True,
                    "domain": domain
                }
            }
        
        return {
            "score": 0,
            "raw_value": "Not Disposable",
            "details": {
                "disposable": False,
                "domain": domain
            }
        }


class EmailDomainAge(BaseSource):
    """Check email domain age using WHOIS"""
    name = "DomainAge"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, email: str) -> Dict[str, Any]:
        if "@" not in email:
            return {"score": None, "raw_value": "Invalid Email", "details": {}}
        
        domain = email.split("@")[1].lower()
        
        # Use RDAP to check domain age
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
            return {"score": None, "raw_value": "Domain Not Found", "details": {"domain": domain}}
        
        creation_date = None
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                creation_date = event.get("eventDate", "")[:10]
                break
        
        if not creation_date:
            return {"score": None, "raw_value": "Age Unknown", "details": {"domain": domain}}
        
        # Calculate age
        from datetime import datetime
        try:
            created = datetime.strptime(creation_date, "%Y-%m-%d")
            age_days = (datetime.now() - created).days
            age_years = age_days // 365
        except:
            return {"score": None, "raw_value": f"Created: {creation_date}", "details": {"domain": domain, "creation_date": creation_date}}
        
        # Newer domains are more suspicious
        if age_days < 30:
            score = 80
            raw = f"Very New ({age_days} days)"
        elif age_days < 180:
            score = 50
            raw = f"New ({age_days} days)"
        elif age_years < 1:
            score = 30
            raw = f"{age_days} days old"
        else:
            score = 0
            raw = f"{age_years} years old"
        
        return {
            "score": score,
            "raw_value": raw,
            "details": {
                "domain": domain,
                "creation_date": creation_date,
                "age_days": age_days,
                "age_years": age_years
            }
        }


class EmailFormatValidator(BaseSource):
    """Validate email format and extract components"""
    name = "Validator"
    requires_api_key = False
    rate_limit_delay = 0
    
    def lookup(self, email: str) -> Dict[str, Any]:
        import re
        
        # Basic email regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        is_valid = bool(re.match(email_pattern, email))
        
        if not is_valid:
            return {
                "score": 100,
                "raw_value": "Invalid Format",
                "details": {"valid": False}
            }
        
        local_part = email.split("@")[0]
        domain = email.split("@")[1].lower()
        
        # Check for suspicious patterns
        suspicious = False
        reasons = []
        
        if len(local_part) < 3:
            suspicious = True
            reasons.append("Very short local part")
        
        if re.match(r'^[0-9]+$', local_part):
            suspicious = True
            reasons.append("All numeric local part")
        
        if re.match(r'^[a-z]{20,}$', local_part):
            suspicious = True
            reasons.append("Unusually long random string")
        
        score = 40 if suspicious else 0
        
        return {
            "score": score,
            "raw_value": "Valid" + (" - Suspicious" if suspicious else ""),
            "details": {
                "valid": True,
                "local_part": local_part,
                "domain": domain,
                "suspicious": suspicious,
                "reasons": reasons
            }
        }


class HunterIO(BaseSource):
    """Hunter.io - Email verification and domain search"""
    name = "Hunter"
    requires_api_key = True
    rate_limit_delay = 1.0
    
    def lookup(self, email: str) -> Dict[str, Any]:
        url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={self.api_key}"
        
        try:
            response = self.session.get(url, timeout=10)
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if "errors" in data:
            return {"score": None, "raw_value": data["errors"][0].get("details", "Error"), "details": {}}
        
        result = data.get("data", {})
        status = result.get("status", "unknown")
        
        score = 0
        if status == "invalid":
            score = 60
        elif status == "unknown":
            score = 30
        elif status == "risky":
            score = 50
        
        return {
            "score": score,
            "raw_value": f"{status.title()} ({result.get('score', 0)}%)",
            "details": {
                "status": status,
                "result": result.get("result"),
                "confidence_score": result.get("score"),
                "regexp": result.get("regexp", True),
                "gibberish": result.get("gibberish", False),
                "disposable": result.get("disposable", False),
                "webmail": result.get("webmail", False),
                "mx_records": result.get("mx_records", True),
                "smtp_server": result.get("smtp_server", True),
                "smtp_check": result.get("smtp_check", True),
                "accept_all": result.get("accept_all", False),
                "block": result.get("block", False),
                "sources": result.get("sources", []),
            }
        }


class Dehashed(BaseSource):
    """Dehashed - Breach database search"""
    name = "Dehashed"
    requires_api_key = True
    rate_limit_delay = 2.0
    
    def lookup(self, email: str) -> Dict[str, Any]:
        url = f"https://api.dehashed.com/search?query=email:{email}"
        
        try:
            # API key format: email:api_key
            if ":" in self.api_key:
                auth_email, api_key = self.api_key.split(":", 1)
            else:
                return {"score": None, "raw_value": "Invalid API Key Format", "details": {}}
            
            response = self.session.get(
                url,
                auth=(auth_email, api_key),
                headers={"Accept": "application/json"},
                timeout=15
            )
            
            if response.status_code == 401:
                return {"score": None, "raw_value": "Auth Failed", "details": {}}
            if response.status_code == 429:
                return {"score": None, "raw_value": "Rate Limited", "details": {}}
                
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        entries = data.get("entries", []) or []
        total = data.get("total", 0)
        
        if total == 0:
            return {"score": 0, "raw_value": "No Breaches", "details": {"total": 0}}
        
        # Score based on number of breaches
        score = min(100, total * 10)
        
        return {
            "score": score,
            "raw_value": f"{total} breach records",
            "details": {
                "total": total,
                "entries": [
                    {
                        "database_name": e.get("database_name"),
                        "username": e.get("username"),
                        "password": "***" if e.get("password") else None,
                        "hashed_password": "***" if e.get("hashed_password") else None,
                        "ip_address": e.get("ip_address"),
                        "phone": e.get("phone"),
                    }
                    for e in entries[:10]
                ]
            }
        }


class LeakCheck(BaseSource):
    """LeakCheck.io - Credential leak database"""
    name = "LeakCheck"
    requires_api_key = True
    rate_limit_delay = 1.0
    
    def lookup(self, email: str) -> Dict[str, Any]:
        url = f"https://leakcheck.io/api/public?check={email}"
        headers = {"X-API-Key": self.api_key}
        
        try:
            response = self.session.get(url, headers=headers, timeout=10)
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if not data.get("success"):
            error = data.get("error", "Unknown error")
            return {"score": None, "raw_value": error, "details": {}}
        
        found = data.get("found", 0)
        sources = data.get("sources", [])
        
        if found == 0:
            return {"score": 0, "raw_value": "No Leaks", "details": {"found": 0}}
        
        score = min(100, found * 15)
        
        return {
            "score": score,
            "raw_value": f"{found} leaks in {len(sources)} sources",
            "details": {
                "found": found,
                "sources": sources,
                "fields": data.get("fields", [])
            }
        }


class GoogleSafeBrowsingEmail(BaseSource):
    """Google Safe Browsing - Check email domain"""
    name = "GoogleSB"
    requires_api_key = True
    rate_limit_delay = 0.5
    
    def lookup(self, email: str) -> Dict[str, Any]:
        if "@" not in email:
            return {"score": None, "raw_value": "Invalid", "details": {}}
        
        domain = email.split("@")[1].lower()
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.api_key}"
        
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
            return {"score": 0, "raw_value": "Domain Safe", "details": {"safe": True, "domain": domain}}
        
        threat_types = list(set([m.get("threatType") for m in matches]))
        
        return {
            "score": 100,
            "raw_value": f"UNSAFE: {', '.join(threat_types)}",
            "details": {
                "threat_types": threat_types,
                "domain": domain,
                "phishing": "SOCIAL_ENGINEERING" in threat_types,
                "malware": "MALWARE" in threat_types,
            }
        }


class MailboxValidator(BaseSource):
    """Check MX records and mail server existence"""
    name = "MXCheck"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, email: str) -> Dict[str, Any]:
        if "@" not in email:
            return {"score": None, "raw_value": "Invalid", "details": {}}
        
        domain = email.split("@")[1].lower()
        
        # Check MX via DNS over HTTPS
        url = f"https://dns.google/resolve?name={domain}&type=MX"
        
        try:
            response = self.session.get(url, timeout=10)
            data = response.json()
        except:
            return {"score": None, "raw_value": "Error", "details": {}}
        
        if data.get("Status") != 0:
            return {
                "score": 80,
                "raw_value": "No MX Records",
                "details": {"has_mx": False, "domain": domain}
            }
        
        mx_records = []
        for answer in data.get("Answer", []):
            if answer.get("type") == 15:  # MX record
                mx_records.append(answer.get("data", "").split()[-1].rstrip("."))
        
        if not mx_records:
            return {
                "score": 60,
                "raw_value": "No MX Found",
                "details": {"has_mx": False, "domain": domain}
            }
        
        # Known free/webmail providers
        free_providers = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com", "protonmail.com"}
        is_free = domain in free_providers or any(fp in mx for mx in mx_records for fp in ["google", "outlook", "yahoo"])
        
        return {
            "score": 0,
            "raw_value": f"{len(mx_records)} MX" + (" (Free)" if is_free else ""),
            "details": {
                "has_mx": True,
                "mx_records": mx_records[:5],
                "domain": domain,
                "free_provider": is_free
            }
        }


class GravatarLookup(BaseSource):
    """Gravatar - Profile photo and account info from email hash"""
    name = "Gravatar"
    requires_api_key = False
    rate_limit_delay = 0.5
    
    def lookup(self, email: str) -> Dict[str, Any]:
        import hashlib
        
        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        
        # Check profile JSON
        profile_url = f"https://www.gravatar.com/{email_hash}.json"
        try:
            response = self.session.get(profile_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                entry = data.get("entry", [{}])[0]
                
                display_name = entry.get("displayName", "")
                profile_url_link = entry.get("profileUrl", "")
                about_me = entry.get("aboutMe", "")
                current_location = entry.get("currentLocation", "")
                
                # Extract linked accounts
                accounts = []
                for acc in entry.get("accounts", []):
                    accounts.append(f"{acc.get('shortname', '')}: {acc.get('url', '')}")
                
                # Extract photos
                photos = [p.get("value", "") for p in entry.get("photos", [])]
                
                # Names
                name_info = entry.get("name", {})
                full_name = ""
                if name_info:
                    full_name = f"{name_info.get('givenName', '')} {name_info.get('familyName', '')}".strip()
                
                return {
                    "score": None,
                    "raw_value": f"Found - {display_name or full_name or 'Profile exists'}",
                    "details": {
                        "display_name": display_name,
                        "full_name": full_name,
                        "profile_url": profile_url_link,
                        "about_me": about_me,
                        "location": current_location,
                        "avatar_url": photos[0] if photos else f"https://www.gravatar.com/avatar/{email_hash}",
                        "linked_accounts": accounts[:5],
                        "hash": email_hash,
                    }
                }
            else:
                return {
                    "score": None,
                    "raw_value": "No Profile",
                    "details": {"hash": email_hash}
                }
        except Exception:
            return {"score": None, "raw_value": "Error", "details": {}}


class GitHubEmail(BaseSource):
    """GitHub - Find GitHub account linked to email"""
    name = "GitHub"
    requires_api_key = False
    rate_limit_delay = 2.0
    
    def lookup(self, email: str) -> Dict[str, Any]:
        # Search GitHub users by email
        url = "https://api.github.com/search/users"
        params = {"q": f"{email} in:email"}
        headers = {"Accept": "application/vnd.github.v3+json"}
        
        try:
            response = self.session.get(url, params=params, headers=headers, timeout=10)
            
            if response.status_code == 403:
                return {"score": None, "raw_value": "Rate Limited", "details": {}}
            
            if response.status_code != 200:
                return {"score": None, "raw_value": "Not Found", "details": {}}
            
            data = response.json()
            total = data.get("total_count", 0)
            
            if total == 0:
                return {"score": None, "raw_value": "No GitHub Account", "details": {}}
            
            users = data.get("items", [])
            user_details = []
            
            for user in users[:3]:
                username = user.get("login", "")
                profile_url = user.get("html_url", "")
                avatar = user.get("avatar_url", "")
                user_type = user.get("type", "User")
                
                # Get more details
                user_info = {}
                try:
                    detail_resp = self.session.get(user.get("url", ""), headers=headers, timeout=10)
                    if detail_resp.status_code == 200:
                        ud = detail_resp.json()
                        user_info = {
                            "name": ud.get("name", ""),
                            "company": ud.get("company", ""),
                            "location": ud.get("location", ""),
                            "bio": ud.get("bio", ""),
                            "public_repos": ud.get("public_repos", 0),
                            "followers": ud.get("followers", 0),
                            "created_at": ud.get("created_at", ""),
                        }
                except:
                    pass
                
                user_details.append({
                    "username": username,
                    "profile_url": profile_url,
                    "avatar": avatar,
                    "type": user_type,
                    **user_info,
                })
            
            primary = user_details[0] if user_details else {}
            display = primary.get("username", "Unknown")
            
            return {
                "score": None,
                "raw_value": f"Found: {display} ({total} match{'es' if total > 1 else ''})",
                "details": {
                    "total_matches": total,
                    "users": user_details,
                    "primary_username": primary.get("username", ""),
                    "primary_name": primary.get("name", ""),
                    "primary_company": primary.get("company", ""),
                    "primary_location": primary.get("location", ""),
                    "primary_bio": primary.get("bio", ""),
                    "public_repos": primary.get("public_repos", 0),
                    "followers": primary.get("followers", 0),
                    "profile_url": primary.get("profile_url", ""),
                    "account_created": primary.get("created_at", ""),
                }
            }
        except Exception:
            return {"score": None, "raw_value": "Error", "details": {}}


class DisifyCheck(BaseSource):
    """Disify - Email disposable/format check with DNS validation"""
    name = "Disify"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, email: str) -> Dict[str, Any]:
        url = f"https://disify.com/api/email/{email}"
        
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                return {"score": None, "raw_value": "Error", "details": {}}
            
            data = response.json()
            
            is_disposable = data.get("disposable", False)
            is_webmail = data.get("webmail", False)
            dns_valid = data.get("dns", False)
            format_valid = data.get("format", False)
            
            if is_disposable:
                score = 80
                status = "Disposable"
            elif not dns_valid:
                score = 60
                status = "Invalid DNS"
            elif not format_valid:
                score = 50
                status = "Invalid Format"
            elif is_webmail:
                score = None
                status = "Webmail"
            else:
                score = None
                status = "Business/Custom"
            
            return {
                "score": score,
                "raw_value": status,
                "details": {
                    "disposable": is_disposable,
                    "webmail": is_webmail,
                    "dns_valid": dns_valid,
                    "format_valid": format_valid,
                    "domain": data.get("domain", ""),
                }
            }
        except Exception:
            return {"score": None, "raw_value": "Error", "details": {}}


class EvaEmailCheck(BaseSource):
    """EVA - Email validation with SMTP and deliverability check"""
    name = "EVA"
    requires_api_key = False
    rate_limit_delay = 1.0
    
    def lookup(self, email: str) -> Dict[str, Any]:
        url = f"https://api.eva.pingutil.com/email?email={email}"
        
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code != 200:
                return {"score": None, "raw_value": "Error", "details": {}}
            
            data = response.json()
            d = data.get("data", {})
            
            deliverable = d.get("deliverable")
            valid_syntax = d.get("valid_syntax", False)
            is_disposable = d.get("disposable", False)
            is_webmail = d.get("webmail", False)
            is_catchall = d.get("catch_all", False)
            is_gibberish = d.get("gibberish", False)
            has_mx = d.get("mx_record", False)
            smtp_check = d.get("smtp_check", False)
            
            if is_disposable:
                score = 80
                status = "Disposable"
            elif deliverable == False:
                score = 50
                status = "Not Deliverable"
            elif is_gibberish:
                score = 40
                status = "Gibberish Username"
            elif deliverable == True:
                score = None
                status = "Deliverable"
            else:
                score = None
                status = "Unknown"
            
            return {
                "score": score,
                "raw_value": status,
                "details": {
                    "deliverable": deliverable,
                    "valid_syntax": valid_syntax,
                    "disposable": is_disposable,
                    "webmail": is_webmail,
                    "catch_all": is_catchall,
                    "gibberish": is_gibberish,
                    "has_mx_record": has_mx,
                    "smtp_check": smtp_check,
                }
            }
        except Exception:
            return {"score": None, "raw_value": "Error", "details": {}}


# All email sources
EMAIL_SOURCES = [
    EmailFormatValidator,
    EmailRepIO,
    DisposableEmailCheck,
    GravatarLookup,
    GitHubEmail,
    DisifyCheck,
    EvaEmailCheck,
    EmailDomainAge,
    HaveIBeenPwnedEmail,
    HunterIO,
    Dehashed,
    LeakCheck,
    GoogleSafeBrowsingEmail,
    MailboxValidator,
]
