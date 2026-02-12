"""
Base class for all OSINT sources
"""
import os
import time
import requests
import urllib3
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress SSL warnings when verification is disabled (corporate proxies)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Read network config from environment
SSL_VERIFY = os.getenv("SSL_VERIFY", "false").lower() in ("true", "1", "yes")
HTTP_PROXY = os.getenv("HTTP_PROXY", "")
HTTPS_PROXY = os.getenv("HTTPS_PROXY", "")
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "15"))


class BaseSource(ABC):
    """Base class for OSINT source integrations"""
    
    name: str = "BaseSource"
    requires_api_key: bool = False
    rate_limit_delay: float = 1.0
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "OSINT-AIO/1.0"
        })
        
        # === SSL VERIFICATION ===
        # Disabled by default for corporate networks with proxy/MITM certs
        # Set SSL_VERIFY=true in .env if you want strict verification
        self.session.verify = SSL_VERIFY
        
        # === PROXY SUPPORT ===
        # Set HTTP_PROXY / HTTPS_PROXY in .env for corporate proxies
        if HTTP_PROXY or HTTPS_PROXY:
            self.session.proxies = {
                "http": HTTP_PROXY or HTTPS_PROXY,
                "https": HTTPS_PROXY or HTTP_PROXY,
            }
        
        # === RETRY LOGIC ===
        # Auto-retry on transient failures (502, 503, 504, connection reset)
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self._last_request_time = 0
    
    def _rate_limit(self):
        """Enforce rate limiting between requests"""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self._last_request_time = time.time()
    
    def _request(self, method: str, url: str, **kwargs) -> Optional[Dict]:
        """Make HTTP request with error handling"""
        self._rate_limit()
        
        # Use configurable timeout
        if "timeout" not in kwargs:
            kwargs["timeout"] = REQUEST_TIMEOUT
        
        try:
            response = self.session.request(method, url, **kwargs)
            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError:
                    return None
            elif response.status_code == 404:
                return None  # Not found is valid response
            else:
                return None  # Silently handle other errors
        except requests.exceptions.SSLError:
            return None  # SSL errors (cert verification, proxy issues)
        except requests.exceptions.ProxyError:
            return None  # Proxy connection failures
        except requests.exceptions.ConnectionError:
            return None  # Network unreachable, DNS failures
        except requests.exceptions.Timeout:
            return None  # Request timed out
        except requests.exceptions.RequestException:
            return None  # Any other request error
        except Exception:
            return None
    
    @abstractmethod
    def lookup(self, ioc: str) -> Dict[str, Any]:
        """
        Lookup IOC and return results
        
        Returns dict with:
            - score: 0-100 (0=clean, 100=malicious) or None if unavailable
            - raw_value: The raw value to display in spreadsheet
            - details: Additional info dict
        """
        pass
    
    def is_available(self) -> bool:
        """Check if source is available (has required API key)"""
        if self.requires_api_key and not self.api_key:
            return False
        return True
