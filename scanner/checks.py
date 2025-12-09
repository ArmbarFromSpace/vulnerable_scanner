import requests  # For GET requests
# urljoin for paths in D, urlparse for scheme/params in A/B/E/F
from urllib.parse import urljoin, urlparse

# A: Headers (check 5 headers for missing/OK)


# Response for headers, url for HSTS scheme
def check_security_headers(response, url):
    findings = []  # List to hold 5 results
    # OWASP for all (spec mapping)
    owasp = "A05:2021 – Security Misconfiguration"
    # Check if https for HSTS skip (spec "when using HTTPS")
    is_https = urlparse(url).scheme == 'https'
    headers_to_check = ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options',  # 5 headers from spec
                        'Strict-Transport-Security', 'Referrer-Policy']
    for header_name in headers_to_check:  # Loop each - spec "for each"
        # Skip if not https
        if header_name == 'Strict-Transport-Security' and not is_https:
            findings.append(
                f"{header_name}: Info - skipped (not HTTPS) ({owasp})")
        elif header_name in response.headers:  # Check if present
            # Spec OK
            findings.append(f"{header_name}: OK - present ({owasp})")
        else:  # Missing
            # Default why (spec "briefly explain")
            explain = "Blocks attacks like XSS"
            if header_name == 'Content-Security-Policy':
                explain = "Blocks unauthorized scripts/resources to prevent XSS."
            elif header_name == 'X-Frame-Options':
                explain = "Prevents clickjacking by blocking iframe embedding."
            elif header_name == 'X-Content-Type-Options':
                explain = "Stops MIME type sniffing attacks."
            elif header_name == 'Strict-Transport-Security':
                explain = "Enforces HTTPS to prevent MITM attacks."
            else:  # Referrer-Policy
                explain = "Controls referrer info to protect privacy."
            # Spec Warning + explain
            findings.append(
                f"{header_name}: Warning - missing, why? {explain} ({owasp})")
    return findings  # List of 5 strings for report

# B: HTTPS (check scheme and cert)


def check_https(url):
    findings = []  # List for 1 result
    owasp = "A05:2021 – Security Misconfiguration"  # OWASP
    if 'http://' in url:  # Spec "starts with http://" — Warning
        findings.append(f"HTTPS: Warning - No HTTPS in use ({owasp})")
    else:  # https
        try:
            # Spec cert verification
            r = requests.get(url, verify=True, timeout=5)
            findings.append(f"HTTPS: OK - valid cert ({owasp})")
        except requests.exceptions.SSLError:  # Spec cert error
            findings.append(f"HTTPS: Warning - cert error ({owasp})")
        except:  # Other error
            findings.append(f"HTTPS: Info - check failed ({owasp})")
    return findings  # 1 string

# C: Fingerprint (check Server/X-Powered-By for tech/version)


def check_server_fingerprint(response):
    findings = []  # List for 0-2 Infos
    owasp = "A06:2021 – Vulnerable and Outdated Components"  # OWASP
    if 'Server' in response.headers:  # Spec "inspect Server"
        value = response.headers['Server']  # Get value
        # Pull tech/version
        tech = value.split('/')[0] if '/' in value else value
        # Spec Info + header
        findings.append(
            f"Server: Info - {value} (tech: {tech}) from Server header ({owasp})")
    if 'X-Powered-By' in response.headers:  # Spec "X-Powered-By"
        value = response.headers['X-Powered-By']
        tech = value.split('/')[0] if '/' in value else value
        findings.append(
            f"X-Powered-By: Info - {value} (tech: {tech}) from X-Powered-By header ({owasp})")
    if not findings:  # No headers = OK
        findings.append(
            f"Fingerprint: OK - no Server or X-Powered-By headers ({owasp})")
    return findings  # List of strings

# D: Dir Listing (probe 4 paths for open listings)


def check_directory_listing(url):
    findings = []  # List for 0+ Warnings
    paths = ['/', '/admin/', '/test/', '/backup/']  # Spec paths
    for p in paths:
        full_url = urljoin(url, p)  # Build full path
        r = requests.get(full_url, timeout=5)  # GET response
        if 'Index of /' in r.text or 'It works!' in r.text:  # Spec strings
            # Spec Warning + explain
            findings.append(
                f"Dir {p}: Warning - open listing/default (exposes files) (A05:2021 – Security Misconfiguration)")
    return findings  # Empty = OK

# E: XSS (replace param with payload, check reflection)


def check_basic_xss(url):
    findings = []  # List for 0-1 result
    parsed = urlparse(url)  # Get clean query (ignores #/)
    if not parsed.query:  # Spec "with query parameters"—skip if no
        return findings
    payload = "<script>alert('xss')</script>"  # Spec payload
    query_parts = parsed.query.split('&')  # Split params
    if query_parts and '=' in query_parts[0]:  # First param
        key = query_parts[0].split('=')[0]  # Key (e.g., 'q')
        # Replace value
        new_query = parsed.query.replace(f"{key}=", f"{key}={payload}", 1)
        new_url = urlparse(url)._replace(query=new_query).geturl()  # Rebuild
        r = requests.get(new_url, timeout=5)  # Send
        if payload in r.text:  # Spec "exact string unescaped"
            # Spec message
            findings.append(
                "XSS: Warning - Reflected input without encoding – potential XSS risk (A03:2021 – Injection (XSS))")
    return findings  # List

# F: SQLi (replace param with payloads, check errors)


def check_basic_sqli(url):
    findings = []  # List for 0-1 result
    parsed = urlparse(url)  # Clean query
    if not parsed.query:  # Spec "query parameters like ?id=1"—skip
        return findings
    payloads = ["1'", "1 OR 1=1"]  # Spec variations
    query_parts = parsed.query.split('&')
    if query_parts and '=' in query_parts[0]:
        key = query_parts[0].split('=')[0]
        for p in payloads:
            new_query = parsed.query.replace(f"{key}=", f"{key}={p}", 1)
            new_url = urlparse(url)._replace(query=new_query).geturl()
            r = requests.get(new_url, timeout=5)
            if r.status_code == 500 or 'syntax error' in r.text.lower():  # Spec errors
                # Spec message
                findings.append(
                    "SQLi: Warning - potential SQL injection risk (error-based) (A03:2021 – Injection)")
                break
    return findings  # List
