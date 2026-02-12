"""
Configuration for OSINT All-In-One
API keys loaded from environment variables or .env file
"""
import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
ABUSECH_API_KEY = os.getenv("ABUSECH_API_KEY", "")
HYBRIDANALYSIS_API_KEY = os.getenv("HYBRIDANALYSIS_API_KEY", "")
GOOGLE_SAFEBROWSING_API_KEY = os.getenv("GOOGLE_SAFEBROWSING_API_KEY", "")
IPQS_API_KEY = os.getenv("IPQS_API_KEY", "")
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
DEHASHED_API_KEY = os.getenv("DEHASHED_API_KEY", "")
LEAKCHECK_API_KEY = os.getenv("LEAKCHECK_API_KEY", "")
