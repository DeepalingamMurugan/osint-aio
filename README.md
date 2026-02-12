# osint-aio 

osint-aio is a comprehensive Open Source Intelligence (OSINT) analysis tool designed to perform recursive analysis across multiple data types. Built with Python and Streamlit, it provides a unified interface for investigating Indicators of Compromise (IOCs) including IP addresses, file hashes, domains, URLs, and email addresses.

The tool aggregates data from various threat intelligence sources, normalizes the results, and attempts to correlate findings to uncover related infrastructure and threats.

## Features

- **Universal Data Classification**: Automatically detects and classifies input data types (IP, Hash, Domain, URL, Email).
- **Multi-Source Aggregation**: Queries multiple threat intelligence APIs concurrently.
- **Recursive Analysis**: Extracts and analyzes related artifacts found in initial results (e.g., finding IPs associated with a domain).
- **Data Refanging**: Automatically converts "defanged" IOCs (e.g., `hxxp://example[.]com`) to standard formats for analysis.
- **Unified Summary**: Presents a consolidated view of threat scores, geographic location, ISP/ASN details, and security flags.
- **Visual Interface**: Clean, dark-mode web interface powered by Streamlit.

## Supported Data Types and Sources

### IP Addresses

Queries services for geolocation, reputation, and threat intelligence.

- **Sources**: AbuseIPDB, VirusTotal, AlienVault OTX, ThreatFox, IPQS, etc.
- **Analysis**: Location, ASN, ISP, Proxy/VPN/Tor detection, Threat Scores.

### File Hashes

Analyzes MD5, SHA1, and SHA256 hashes for malware/threat details.

- **Sources**: VirusTotal, MalwareBazaar, ThreatFox, HybridAnalysis, OTX.
- **Analysis**: File type identification, YARA rules, Sandbox verdicts, Vendor detections.

### Domains

Investigates domain registration and infrastructure.

- **Sources**: VirusTotal, URLScan, AlienVault OTX, Whois.
- **Analysis**: Registrar info, Creation/Expiry dates, DNS records (A, MX, NS, TXT), Email security (SPF/DMARC).

### URLs

Scans URLs for phishing, malware, and improved classification.

- **Sources**: URLScan, VirusTotal, Google Safe Browsing, URLhaus.
- **Analysis**: Page screenshots (via URLScan), Final URL resolution, Page server info.

### Emails

Checks email addresses for reputation, leaks, and validity.

- **Sources**: HIBP (Have I Been Pwned), Hunter, EmailRep, LeakCheck, Dehashed.
- **Analysis**: Breach history, Disposable checks, Domain reputation, MX record validation.

## Installation

### Prerequisites

- Python 3.12 or higher
- pip (Python package installer)

### Setup

1.  Clone the repository:

    ```bash
    git clone repo link
    cd osint-aio
    ```

2.  Create and activate a virtual environment (recommended):

    ```bash
    python -m venv .venv
    # Windows
    .venv\Scripts\activate
    # Linux/Mac
    source .venv/bin/activate
    ```

3.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

The application requires API keys for various services to function correctly. These keys should be stored in a `.env` file or `config.py`.

1.  Rename or create a `.env` file in the root directory.
2.  Add your API keys in the following format:

```env
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
OTX_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
ABUSECH_API_KEY=your_key_here
HYBRIDANALYSIS_API_KEY=your_key_here
GOOGLE_SAFEBROWSING_API_KEY=your_key_here
IPQS_API_KEY=your_key_here
HUNTER_API_KEY=your_key_here
HIBP_API_KEY=your_key_here
DEHASHED_API_KEY=your_key_here
LEAKCHECK_API_KEY=your_key_here
```

Note: Some modules may function with limited capabilities without API keys, but full functionality requires valid credentials for the respective services.

## Usage

1.  Start the Streamlit application:

    ```bash
    streamlit run app.py
    ```

2.  The application will open in your default web browser (usually at `http://localhost:8501`).

3.  Enter an Indicator of Compromise (IP, Domain, Hash, URL, or Email) in the search bar.

4.  View the aggregated results, summary tables, and raw JSON data from each source.

## Project Structure

- `app.py`: Main application entry point and UI logic.
- `config.py`: Configuration management and environment variable loading.
- `constants.py`: Static data, country codes, and TLD reference lists.
- `requirements.txt`: Python package dependencies.
- `sources/`: Directory containing source-specific modules.
  - `base.py`: Base classes for source integrations.
  - `ip_sources.py`: Modules for IP address analysis.
  - `domain_sources.py`: Modules for domain analysis.
  - `url_sources.py`: Modules for URL analysis.
  - `hash_sources.py`: Modules for file hash analysis.
  - `email_sources.py`: Modules for email address analysis.
