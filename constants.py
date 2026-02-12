"""
Constants for OSINT All-In-One
Centralized location for all constant mappings and lists
"""

# ============================================================================
# COUNTRY CODES - ISO 3166-1 alpha-2 codes to country names
# ============================================================================
COUNTRY_NAMES = {
    # North America
    "US": "United States",
    "CA": "Canada",
    "MX": "Mexico",
    
    # Central America & Caribbean
    "GT": "Guatemala",
    "BZ": "Belize",
    "HN": "Honduras",
    "SV": "El Salvador",
    "NI": "Nicaragua",
    "CR": "Costa Rica",
    "PA": "Panama",
    "CU": "Cuba",
    "JM": "Jamaica",
    "HT": "Haiti",
    "DO": "Dominican Republic",
    "PR": "Puerto Rico",
    "TT": "Trinidad and Tobago",
    "BB": "Barbados",
    "BS": "Bahamas",
    
    # South America
    "BR": "Brazil",
    "AR": "Argentina",
    "CL": "Chile",
    "CO": "Colombia",
    "PE": "Peru",
    "VE": "Venezuela",
    "EC": "Ecuador",
    "BO": "Bolivia",
    "PY": "Paraguay",
    "UY": "Uruguay",
    "GY": "Guyana",
    "SR": "Suriname",
    
    # Western Europe
    "GB": "United Kingdom",
    "UK": "United Kingdom",  # Alternative code
    "IE": "Ireland",
    "FR": "France",
    "DE": "Germany",
    "NL": "Netherlands",
    "BE": "Belgium",
    "LU": "Luxembourg",
    "CH": "Switzerland",
    "AT": "Austria",
    "LI": "Liechtenstein",
    "MC": "Monaco",
    
    # Northern Europe
    "SE": "Sweden",
    "NO": "Norway",
    "DK": "Denmark",
    "FI": "Finland",
    "IS": "Iceland",
    "EE": "Estonia",
    "LV": "Latvia",
    "LT": "Lithuania",
    
    # Southern Europe
    "IT": "Italy",
    "ES": "Spain",
    "PT": "Portugal",
    "GR": "Greece",
    "MT": "Malta",
    "CY": "Cyprus",
    "AD": "Andorra",
    "SM": "San Marino",
    "VA": "Vatican City",
    
    # Eastern Europe
    "RU": "Russia",
    "UA": "Ukraine",
    "PL": "Poland",
    "CZ": "Czech Republic",
    "SK": "Slovakia",
    "HU": "Hungary",
    "RO": "Romania",
    "BG": "Bulgaria",
    "MD": "Moldova",
    "BY": "Belarus",
    
    # Balkans
    "RS": "Serbia",
    "HR": "Croatia",
    "SI": "Slovenia",
    "BA": "Bosnia and Herzegovina",
    "ME": "Montenegro",
    "MK": "North Macedonia",
    "AL": "Albania",
    "XK": "Kosovo",
    
    # Middle East
    "TR": "Turkey",
    "IL": "Israel",
    "PS": "Palestine",
    "LB": "Lebanon",
    "SY": "Syria",
    "JO": "Jordan",
    "IQ": "Iraq",
    "IR": "Iran",
    "SA": "Saudi Arabia",
    "AE": "UAE",
    "KW": "Kuwait",
    "QA": "Qatar",
    "BH": "Bahrain",
    "OM": "Oman",
    "YE": "Yemen",
    
    # Central Asia
    "KZ": "Kazakhstan",
    "UZ": "Uzbekistan",
    "TM": "Turkmenistan",
    "TJ": "Tajikistan",
    "KG": "Kyrgyzstan",
    "AF": "Afghanistan",
    
    # South Asia
    "IN": "India",
    "PK": "Pakistan",
    "BD": "Bangladesh",
    "LK": "Sri Lanka",
    "NP": "Nepal",
    "BT": "Bhutan",
    "MV": "Maldives",
    
    # East Asia
    "CN": "China",
    "JP": "Japan",
    "KR": "South Korea",
    "KP": "North Korea",
    "TW": "Taiwan",
    "HK": "Hong Kong",
    "MO": "Macau",
    "MN": "Mongolia",
    
    # Southeast Asia
    "TH": "Thailand",
    "VN": "Vietnam",
    "MY": "Malaysia",
    "SG": "Singapore",
    "ID": "Indonesia",
    "PH": "Philippines",
    "MM": "Myanmar",
    "KH": "Cambodia",
    "LA": "Laos",
    "BN": "Brunei",
    "TL": "Timor-Leste",
    
    # Oceania
    "AU": "Australia",
    "NZ": "New Zealand",
    "FJ": "Fiji",
    "PG": "Papua New Guinea",
    "WS": "Samoa",
    "TO": "Tonga",
    "VU": "Vanuatu",
    "SB": "Solomon Islands",
    "NC": "New Caledonia",
    "PF": "French Polynesia",
    "GU": "Guam",
    
    # North Africa
    "EG": "Egypt",
    "LY": "Libya",
    "TN": "Tunisia",
    "DZ": "Algeria",
    "MA": "Morocco",
    "SD": "Sudan",
    
    # West Africa
    "NG": "Nigeria",
    "GH": "Ghana",
    "CI": "Ivory Coast",
    "SN": "Senegal",
    "ML": "Mali",
    "BF": "Burkina Faso",
    "NE": "Niger",
    "TG": "Togo",
    "BJ": "Benin",
    "LR": "Liberia",
    "SL": "Sierra Leone",
    "GN": "Guinea",
    "GM": "Gambia",
    "GW": "Guinea-Bissau",
    "CV": "Cape Verde",
    "MR": "Mauritania",
    
    # East Africa
    "KE": "Kenya",
    "TZ": "Tanzania",
    "UG": "Uganda",
    "RW": "Rwanda",
    "BI": "Burundi",
    "ET": "Ethiopia",
    "ER": "Eritrea",
    "DJ": "Djibouti",
    "SO": "Somalia",
    "SS": "South Sudan",
    "MG": "Madagascar",
    "MU": "Mauritius",
    "SC": "Seychelles",
    "KM": "Comoros",
    "RE": "Réunion",
    
    # Central Africa
    "CD": "DR Congo",
    "CG": "Congo",
    "CF": "Central African Republic",
    "CM": "Cameroon",
    "TD": "Chad",
    "GA": "Gabon",
    "GQ": "Equatorial Guinea",
    "ST": "São Tomé and Príncipe",
    "AO": "Angola",
    
    # Southern Africa
    "ZA": "South Africa",
    "ZW": "Zimbabwe",
    "ZM": "Zambia",
    "BW": "Botswana",
    "NA": "Namibia",
    "MZ": "Mozambique",
    "MW": "Malawi",
    "LS": "Lesotho",
    "SZ": "Eswatini",
    
    # Special/Other
    "EU": "European Union",
    "AP": "Asia Pacific",
    "XX": "Unknown",
    "ZZ": "Unknown",
    "A1": "Anonymous Proxy",
    "A2": "Satellite Provider",
}


# ============================================================================
# COUNTRY CODE TLDs - Two-part country TLDs for domain extraction
# ============================================================================
COUNTRY_TLDS = {
    # United Kingdom
    "co.uk", "org.uk", "net.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    
    # Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    
    # New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
    
    # India
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in", "ac.in", "edu.in", "gov.in",
    
    # Brazil
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br",
    
    # Japan
    "co.jp", "or.jp", "ne.jp", "ac.jp", "ad.jp", "go.jp", "gr.jp", "ed.jp",
    
    # South Korea
    "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr", "re.kr",
    
    # South Africa
    "co.za", "org.za", "net.za", "gov.za", "edu.za", "ac.za",
    
    # China
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    
    # Taiwan
    "com.tw", "net.tw", "org.tw", "gov.tw", "edu.tw",
    
    # Hong Kong
    "com.hk", "net.hk", "org.hk", "gov.hk", "edu.hk",
    
    # Singapore
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    
    # Malaysia
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    
    # Indonesia
    "co.id", "or.id", "web.id", "ac.id", "go.id",
    
    # Thailand
    "co.th", "or.th", "ac.th", "go.th", "in.th",
    
    # Philippines
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    
    # Vietnam
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
    
    # Pakistan
    "com.pk", "net.pk", "org.pk", "gov.pk", "edu.pk",
    
    # Bangladesh
    "com.bd", "net.bd", "org.bd", "gov.bd", "edu.bd",
    
    # Turkey
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr", "biz.tr",
    
    # Israel
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    
    # UAE
    "co.ae", "net.ae", "org.ae", "ac.ae", "gov.ae",
    
    # Saudi Arabia
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
    
    # Egypt
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
    
    # Nigeria
    "com.ng", "net.ng", "org.ng", "gov.ng", "edu.ng",
    
    # Kenya
    "co.ke", "or.ke", "ne.ke", "ac.ke", "go.ke",
    
    # Mexico
    "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
    
    # Argentina
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
    
    # Colombia
    "com.co", "net.co", "org.co", "gov.co", "edu.co",
    
    # Peru
    "com.pe", "net.pe", "org.pe", "gob.pe", "edu.pe",
    
    # Russia
    "com.ru", "net.ru", "org.ru", "gov.ru", "edu.ru",
    
    # Ukraine
    "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua",
    
    # Poland
    "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl",
    
    # Greece
    "com.gr", "net.gr", "org.gr", "gov.gr", "edu.gr",
    
    # Other common patterns
    "or.at", "co.at", "gv.at",  # Austria
    "asso.fr", "tm.fr",  # France
    "co.it",  # Italy
}


# ============================================================================
# DISPOSABLE EMAIL DOMAINS - Known temporary/throwaway email services
# ============================================================================
DISPOSABLE_DOMAINS = {
    # Major disposable email services
    "tempmail.com", "temp-mail.org", "temp-mail.io", "tempmail.net",
    "guerrillamail.com", "guerrillamail.org", "guerrillamail.net", "guerrillamail.info", 
    "guerrillamail.biz", "guerrillamail.de", "grr.la", "guerrillamailblock.com",
    "10minutemail.com", "10minutemail.net", "10minutemail.org", "10minemail.com",
    "mailinator.com", "mailinator.net", "mailinator.org", "mailinator2.com",
    "yopmail.com", "yopmail.fr", "yopmail.net",
    "throwaway.email", "throwawaymail.com",
    "fakeinbox.com", "fakemailgenerator.com",
    "getnada.com", "nada.email",
    "maildrop.cc", "maildrop.ml",
    "trashmail.com", "trashmail.net", "trashmail.org", "trashmail.me",
    "sharklasers.com", "spam4.me",
    "discard.email", "discardmail.com", "discardmail.de",
    "tempr.email", "tempail.com",
    "dropmail.me", "drop.com",
    "mohmal.com", "mohmal.im",
    "emailondeck.com",
    "minutemail.com",
    "mailcatch.com",
    "mytrashmail.com",
    "getairmail.com",
    "mailnesia.com",
    "spamgourmet.com",
    "spamex.com",
    "mailexpire.com",
    "mailnull.com",
    "mailhazard.com",
    "mailmoat.com",
    "meltmail.com",
    "spamhole.com",
    "jetable.org",
    "trashemail.de",
    "wegwerfmail.de", "wegwerfmail.org",
    "einrot.com",
    "spambox.us", "spambox.info",
    "spamcowboy.com", "spamcowboy.net",
    "spamfree24.org", "spamfree24.de",
    "spamspot.com",
    "tempinbox.com",
    "tempemail.net", "tempemail.com",
    "tmpmail.org", "tmpmail.net",
    "nowmymail.com",
    "safetypost.de",
    "spamherelots.com",
    "spamobox.com",
    "tempomail.fr",
    "throwam.com",
    "trbvm.com", "trbvn.com",
    "uggsrock.com",
    "veryrealemail.com",
    "webm4il.info",
    "wh4f.org",
    "willselfdestruct.com",
    "xmaily.com",
    "yapped.net",
    "zoemail.net", "zoemail.org",
    "20minutemail.com",
    "33mail.com",
    "anonymbox.com",
    "armyspy.com",
    "beefmilk.com",
    "cock.li", "cock.email",
    "cuvox.de",
    "dayrep.com",
    "despam.it", "despammed.com",
    "devnullmail.com",
    "emailthe.net",
    "emlpro.com", "emlhub.com",
    "enterto.com",
    "fleckens.hu",
    "freemail.tweakly.net",
    "fudgerub.com",
    "getonemail.com", "getonemail.net",
    "girlsundertheinfluence.com",
    "gowikibooks.com", "gowikicampus.com",
    "hidemail.de", "hidemail.pro",
    "hulapla.de",
    "imgof.com", "imstations.com",
    "incognitomail.com", "incognitomail.org",
    "inboxkitten.com",
    "klzlv.com",
    "kostenlosemailadresse.de",
    "lackmail.net", "lackmail.ru",
    "lags.us",
    "letthemeatspam.com",
    "lolfreak.net",
    "lookugly.com",
    "lr78.com",
    "mailblocks.com",
    "mailcatch.com",
    "mailchop.com",
    "maildu.de",
    "maileater.com",
    "mailfreeonline.com",
    "mailin8r.com",
    "mailismagic.com",
    "mailnator.com",
    "mailscrap.com",
    "mailshell.com",
    "mailslite.com",
    "mailsac.com",
    "mailtemp.info",
    "makemetheking.com",
    "manifestgenerator.com",
    "mintemail.com",
    "mvrht.com",
    "myspaceinc.com", "myspacepimpedup.com",
    "nervmich.net", "nervtmansen.de",
    "nobulk.com",
    "noclickemail.com",
    "nogmailspam.info",
    "nomail.xl.cx", "nomail2me.com",
    "notmailinator.com",
    "notsharingmy.info",
    "objectmail.com",
    "oopi.org",
    "pjjkp.com",
    "politikerclub.de",
    "pookmail.com",
    "privacy.net",
    "putthisinyourspamdatabase.com",
    "quickinbox.com",
    "rcpt.at",
    "reallymymail.com",
    "recode.me",
    "recursor.net",
    "regbypass.com",
    "rhyta.com",
    "rklips.com",
    "rppkn.com",
    "s0ny.net",
    "safe-mail.net",
    "safersignup.de",
    "sandelf.de",
    "saynotospams.com",
    "selfdestructingmail.com",
    "sendspamhere.com",
    "shieldedmail.com",
    "shitmail.me", "shitmail.org",
    "shortmail.net",
    "sibmail.com",
    "slopsbox.com",
    "smellfear.com",
    "snakemail.com",
    "sneakemail.com",
    "snkmail.com",
    "sofort-mail.de",
    "sogetthis.com",
    "soodonims.com",
    "spam.la", "spam.su",
    "spamavert.com",
    "spambob.com", "spambob.net",
    "spambog.com", "spambog.de", "spambog.ru",
    "spamcon.org",
    "spamday.com",
    "spamify.com",
    "spamkill.info",
    "spaml.com",
    "spamstack.net",
    "spamwc.de",
    "supermailer.jp",
    "superstachel.de",
    "survivalmail.net",
    "targetmail.net",
    "teleworm.com", "teleworm.us",
    "thanksnospam.info",
    "thismail.ru", "thismail.net",
    "tokem.co", "tokenmail.de",
    "tradermail.info",
    "trash-amil.com", "trash-mail.at", "trash-mail.de", "trash-mail.com",
    "trashymail.com", "trashymail.net",
    "twinmail.de",
    "upliftnow.com",
    "urben.cz",
    "venompen.com",
    "veryrealemail.com",
    "viditag.com",
    "vpn.st",
    "wasabi.no",
    "wetrainbayarea.com",
    "whopy.com",
    "wuzup.net", "wuzupmail.net",
    "yep.it",
    "yogamaven.com",
    "you-spam.com",
    "ypmail.webarnak.fr.eu.org",
    "zehnminutenmail.de",
    "zippymail.info",
    "zoaxe.com",
}


# ============================================================================
# FREE EMAIL PROVIDERS - Known free/consumer email services
# ============================================================================
FREE_EMAIL_PROVIDERS = {
    # Google
    "gmail.com", "googlemail.com",
    
    # Microsoft
    "outlook.com", "hotmail.com", "live.com", "msn.com", "passport.com",
    "hotmail.co.uk", "hotmail.fr", "hotmail.de", "hotmail.it", "hotmail.es",
    "live.co.uk", "live.fr", "live.de", "live.it", "live.nl",
    "outlook.co.uk", "outlook.fr", "outlook.de",
    
    # Yahoo
    "yahoo.com", "yahoo.co.uk", "yahoo.fr", "yahoo.de", "yahoo.it", 
    "yahoo.es", "yahoo.ca", "yahoo.com.au", "yahoo.co.jp", "yahoo.co.in",
    "ymail.com", "rocketmail.com",
    
    # Apple
    "icloud.com", "me.com", "mac.com",
    
    # AOL
    "aol.com", "aim.com", "compuserve.com", "netscape.net",
    
    # Proton
    "protonmail.com", "protonmail.ch", "proton.me", "pm.me",
    
    # Other popular free providers
    "mail.com", "email.com",
    "zoho.com", "zohomail.com",
    "gmx.com", "gmx.net", "gmx.de", "gmx.at", "gmx.ch",
    "web.de", "t-online.de", "freenet.de",
    "mail.ru", "bk.ru", "inbox.ru", "list.ru", "yandex.com", "yandex.ru",
    "163.com", "126.com", "qq.com", "sina.com",
    "naver.com", "hanmail.net", "daum.net",
    "rediffmail.com", "rediff.com",
    "tutanota.com", "tutamail.com", "tuta.io",
    "fastmail.com", "fastmail.fm",
    "hushmail.com",
    "mailfence.com",
    "startmail.com",
    "runbox.com",
    "disroot.org",
    "riseup.net",
    "cock.li",
}


# ============================================================================
# MALICIOUS INDICATORS - Common malicious file extensions and patterns
# ============================================================================
MALICIOUS_EXTENSIONS = {
    # Executables
    ".exe", ".msi", ".dll", ".scr", ".pif", ".com", ".bat", ".cmd", ".ps1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
    
    # Office macros
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam",
    ".sldm", ".accde", ".accdr", ".accdt",
    
    # Archives (often used for malware delivery)
    ".iso", ".img", ".vhd", ".vhdx",
    
    # Scripts
    ".jar", ".class", ".py", ".pyc", ".pyw", ".rb", ".pl",
    
    # Shortcuts
    ".lnk", ".url", ".desktop",
    
    # Other
    ".reg", ".inf", ".cpl", ".ocx", ".sys", ".drv",
}


# ============================================================================
# SUSPICIOUS PATTERNS - Regex patterns for suspicious content
# ============================================================================
SUSPICIOUS_URL_PATTERNS = [
    r"bit\.ly", r"tinyurl\.com", r"t\.co", r"goo\.gl",  # URL shorteners
    r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",  # IP in URL
    r"@",  # Credential harvesting
    r"-{3,}",  # Multiple dashes
    r"\.tk$", r"\.ml$", r"\.ga$", r"\.cf$", r"\.gq$",  # Free TLDs
]
