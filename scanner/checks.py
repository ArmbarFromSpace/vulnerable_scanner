import requests  # For GET requests
# urljoin for paths in D, urlparse for scheme/params in A/B/E/F
from urllib.parse import urljoin, urlparse

# A: Headers (check 5 headers for missing/OK)


# Response for headers, url for HSTS scheme
def check_security_headers(response, url):
    findings = []  # List to hold 5 dicts
    owasp = "A05:2021 - Security Misconfiguration"
    is_https = urlparse(url).scheme == 'https'
    headers_to_check = ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options',
                        'Strict-Transport-Security', 'Referrer-Policy']
    for header_name in headers_to_check:
        if header_name == 'Strict-Transport-Security' and not is_https:
            findings.append({
                "name": f"{header_name} check",
                "severity": "Info",
                "details": "skipped (not HTTPS endpoint)",
                "owasp": owasp
            })
        elif header_name in response.headers:
            findings.append({
                "name": f"{header_name} Header",
                "severity": "Ok",
                "details": f"present: {header_name}",
                "owasp": owasp
            })
        else:
            explain = ""  # details
            rec = ""  # the fix
            if header_name == 'Content-Security-Policy':
                explain = "Blocks unauthorized scripts/resources to prevent XSS."
                rec = "Add CSP header to block unauthorized scripts/resources (prevents XSS)."
            elif header_name == 'X-Frame-Options':
                explain = "Prevents clickjacking by blocking iframe embedding."
                rec = "Add X-Frame-Options header to prevent clickjacking."
            elif header_name == 'X-Content-Type-Options':
                explain = "Stops MIME type sniffing attacks."
                rec = "Add X-Content-Type-Options: nosniff to stop MIME sniffing."
            elif header_name == 'Strict-Transport-Security':
                explain = "Enforces HTTPS to prevent MITM attacks."
                rec = "Add HSTS header to enforce HTTPS (prevents MITM)."
            else:
                explain = "Controls referrer info to protect privacy."
                rec = "Add Referrer-Policy header to control referrer info (protects privacy)."
            findings.append({
                "name": f"{header_name} check",
                "severity": "Warning",
                "details": explain,
                "owasp": owasp,
                "rec": rec
            })
    return findings

# B: HTTPS (check scheme and cert)


def check_https(url):
    findings = []
    owasp = "A05:2021 - Security Misconfiguration"
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append({
            "name": "HTTPS Usage",
            "severity": "Warning",
            "details": "No HTTPS in use, traffice could be intercepted.",
            "owasp": owasp,
            "rec": "Redirect all HTTP to HTTPS and use HSTS."
        })
        try:
            # Spec cert verification
            r = requests.get(url, verify=True, timeout=5)
            findings.append({
                "name": "HTTPS Usage",
                "severity": "OK",
                "details": "Valid certifcate and secure connection confirmed.",
                "owasp": owasp,
            })
        except requests.exceptions.SSLError:  # Spec cert error
            findings.append({
                "name": "HTTPS Usage",
                "severity": "Warning",
                "details": "Certificate validation failed (e.g., expired or self-signed).",
                "owasp": owasp,
                "rec": "Install a valid TLS certificate"
            })
        except:  # Other error
            findings.append({
                "name": "HTTPS Usage",
                "severity": "Info",
                "details": "Could not verify certificate—check network or server.",
                "owasp": owasp
            })
    return findings  # 1 dict

# C: Fingerprint (check Server/X-Powered-By for tech/version)


def check_server_fingerprint(response):
    findings = []  # List for 0-2 Infos
    owasp = "A06:2021 - Vulnerable and Outdated Components"  # OWASP
    if 'Server' in response.headers:  # Spec "inspect Server"
        value = response.headers['Server']  # Get value
        # Pull tech/version
        tech = value.split('/')[0] if '/' in value else value
        # Spec Info + header
        findings.append({"name": "Powered-By Detection",
                         "severity": "Info",
                         "details": f"Detected {value} (tech: {tech}) from Server header. Check for updates.",
                         "owasp": owasp
                         })
    if 'X-Powered-By' in response.headers:  # Spec "X-Powered-By"
        value = response.headers['X-Powered-By']
        tech = value.split('/')[0] if '/' in value else value
        findings.append({
            "name": "Powered-By Detection",
            "severity": "Info",
            "details": f"Detected {value} (tech: {tech}) from X-Powered-By header.",
            "owasp": owasp
            # "CVE": "IDK maybe later"
        })
        if not findings:  # No headers
            findings.append({
                "name": "Server Fingerprint",
                "severity": "OK",
                "details": "No Server or X-Powered-By headers—good, reduces info leakage.",
                "owasp": owasp
            })
    return findings  # 0-2 infos

# D: Dir Listing (probe 4 paths for open listings)


def check_directory_listing(url):
    findings = []
    owasp = "A05:2021 - Security Misconfiguration"
    paths = ['/', '/admin/', '/test/', '/backup/']  # Spec paths
    any_bad = False
    for p in paths:
        full_url = urljoin(url, p)
        try:
            r = requests.get(full_url, timeout=10)  # GET response
            if 'Index of /' in r.text or 'It works!' in r.text:  # condtions
                findings.append({
                    "name": f"Directory Listing at {p}",
                    "severity": "Warning",
                    "details": f"Response shows open directory or default page at {full_url} (exposes file list).",
                    "owasp": owasp,
                    "rec": "Disable directory indexing in server config (e.g., Apache: Options -Indexes)."
                })
                any
        except:  # in case of timeout
            pass
    if not findings:  # Always return something
        findings.append({
            "name": "Directory Listing Check",
            "severity": "OK",
            "details": "No open directories or default pages found on probed paths.",
            "owasp": owasp
        })
    elif any_bad:  # Opt: Summary if multiples
        findings.insert(0, {  # Prepend summary
            "name": "Directory Listing Summary",
            "severity": "Warning",
            "details": f"{len([f for f in findings if f['severity'] == 'Warning'])} vulnerable paths detected.",
            "owasp": owasp,
            "rec": "Review all directory configs for exposure."
        })
    return findings

# E: XSS (replace param with payload, check reflection)


def check_basic_xss(url):
    findings = []
    owasp = "A03:2021 - Injection (XSS)"
    parsed = urlparse(url)
    if not parsed.query:
        findings.append({
            "name": "XSS Check",
            "severity": "OK",
            "details": "No query parameters present to test for reflection.",
            "owasp": owasp
        })
        return findings
    payload = "<script>alert('xss')</script>"  # Spec payload
    query_parts = parsed.query.split('&')
    any_vuln = False
    for part in query_parts:
        if "=" not in part:
            continue
        key = query_parts[0].split('=')[0]
        new_query = parsed.query.replace(f"{key}=", f"{key}={payload}", 1)
        new_url = urlparse(url)._replace(query=new_query).geturl()
        try:
            r = requests.get(new_url, timeout=5)
            if payload in r.text:  # Your check
                findings.append({
                    "name": "Basic XSS Risk",
                    "severity": "Warning",
                    "details": "Payload reflected unescaped in response HTML potential XSS vector.",
                    "owasp": owasp,
                    "rec": "Sanitize and encode user input before rendering in HTML (e.g., use Jinja autoescape)."
                })
                any_vuln = True
        except:
            pass
    if not findings:
        findings.append({
            "name": "XSS Check",
            "severity": "OK",
            "details": "No reflected payloads detected in any query parameters.",
            "owasp": owasp
        })
    elif any_vuln:
        findings.insert(0, {
            "name": "XSS Summary",
            "severity": "Warning",
            "details": f"{len([f for f in findings if f['severity'] == 'Warning'])} vulnerable parameters found.",
            "owasp": owasp,
            "rec": "Audit all input handling for output encoding."
        })
    return findings

# F: SQLi (replace param with payloads, check errors)


def check_basic_sqli(url):
    findings = []
    owasp = "A03:2021 - Injection"
    parsed = urlparse(url)
    if not parsed.query:
        findings.append({
            "name": "SQLi Check",
            "severity": "OK",
            "details": "No query parameters present to test for errors.",
            "owasp": owasp
        })
        return findings
    payloads = ["1'", "1 OR 1=1"]  # Spec
    query_parts = parsed.query.split('&')
    any_vuln = False
    for part in query_parts:
        if '=' not in part:
            continue
        key, _ = part.split('=', 1)
        param_vuln = False
        for p in payloads:
            new_query = parsed.query.replace(f"{key}=", f"{key}={p}", 1)
            new_url = urlparse(url)._replace(query=new_query).geturl()
            try:
                r = requests.get(new_url, timeout=5)
                if r.status_code == 500 or 'syntax error' in r.text.lower():
                    param_vuln = True
                    break
            except:
                pass
        if param_vuln:
            findings.append({
                "name": f"SQLi Risk in Param '{key}'",
                "severity": "Warning",
                "details": f"Error signals (e.g., 500 or DB error) on payloads for {key}—potential injection point.",
                "owasp": owasp,
                "rec": "Use prepared statements or query parameterization for all DB inputs."
            })
            any_vuln = True
    if not findings:
        findings.append({
            "name": "SQLi Check",
            "severity": "OK",
            "details": "No error-based SQLi signals detected in any query parameters.",
            "owasp": owasp
        })
    elif any_vuln:
        findings.insert(0, {
            "name": "SQLi Summary",
            "severity": "Warning",
            "details": f"{len([f for f in findings if f['severity'] == 'Warning'])} vulnerable parameters found.",
            "owasp": owasp,
            "rec": "Implement input validation and safe querying across the app."
        })
    return findings  # List
