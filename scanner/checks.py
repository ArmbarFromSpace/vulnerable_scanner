import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

# A: Headers (check 5 headers for missing/OK)


def check_security_headers(response, url):
    findings = []
    owasp = "A05:2021 - Security Misconfiguration"

    # check for https
    is_https = urlparse(url).scheme == 'https'

    # define the headers, their short names, and explanations
    headers_to_check = [
        ('Content-Security-Policy', 'CSP',
         "Blocks unauthorized scripts/resources to prevent XSS."),
        ('X-Frame-Options', 'XFO', "Prevents clickjacking by blocking iframe embedding."),
        ('X-Content-Type-Options', 'XCTO', "Stops MIME type sniffing attacks."),
        ('Referrer-Policy', 'RP', "Controls referrer info to protect privacy.")
    ]

    # only check HSTS if using HTTPS
    if is_https:
        headers_to_check.append(
            ('Strict-Transport-Security', 'HSTS', "Enforces HTTPS to prevent MITM attacks."))

    for header_name, short_name, explanation in headers_to_check:
        if header_name in response.headers:
            findings.append({
                "name": f"{short_name} Header",
                "severity": "OK",
                "details": f"{header_name} present: {response.headers[header_name]}",
                "owasp": owasp,
                "rec": None
            })
        else:
            rec = f"Configure the '{header_name}'header."
            findings.append({
                "name": f"Missing {short_name} Header",
                "severity": "Warning",
                "details": f"No {header_name} header found. {explanation}",
                "owasp": owasp,
                "rec": rec
            })
    return findings

# B: HTTPS (check scheme and cert)


def check_https(url):
    findings = []
    owasp = "A05:2021 - Security Misconfiguration"
    parsed = urlparse(url)

    # check Scheme
    if parsed.scheme != "https":
        findings.append({
            "name": "HTTPS Usage",
            "severity": "Warning",
            "details": "No HTTPS in use, traffice could be intercepted.",
            "owasp": owasp,
            "rec": "Redirect all HTTP to HTTPS and use HSTS."
        })
    else:
        # check cert if https
        try:
            requests.get(url, verify=True, timeout=5)
            findings.append({
                "name": "HTTPS Usage",
                "severity": "OK",
                "details": "Valid certifcate and secure connection confirmed.",
                "owasp": owasp,
                "rec": None
            })
        except requests.exceptions.SSLError:  # cert error
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

# C: Fingerprint check


def check_server_fingerprint(response):
    findings = []
    owasp = "A06:2021 - Vulnerable and Outdated Components"

    # check sever header
    if 'Server' in response.headers:
        value = response.headers['Server']
        tech = value.split('/')[0] if '/' in value else value
        findings.append({
            "name": "Powered-By Detection",
            "severity": "Info",
            "details": f"Detected {value} (tech: {tech}) from Server header. Check for updates.",
            "owasp": owasp
        })

    # check X-powered-By header
    if 'X-Powered-By' in response.headers:
        value = response.headers['X-Powered-By']
        tech = value.split('/')[0] if '/' in value else value
        findings.append({
            "name": "Powered-By Detection",
            "severity": "Info",
            "details": f"Detected {value} (tech: {tech}) from X-Powered-By header.",
            "owasp": owasp
            # "CVE": "IDK maybe later"
        })
    if not findings:
        findings.append({
            "name": "Server Fingerprint",
            "severity": "OK",
            "details": "No Server or X-Powered-By headers—good, reduces info leakage.",
            "owasp": owasp
        })
    return findings

# D: Directory Listing check


def check_directory_listing(url):
    findings = []
    owasp = "A05:2021 - Security Misconfiguration"

    # path to probe
    paths = ['/', '/admin/', '/test/', '/backup/',
             '/rest/admin/application-configuration/', '/ftp/']

    vulnerable_keywords = [
        "index of /",
        "parent directory",
        # "last modified",
        # "[dir]",
        # "directory listing"
    ]

    for p in paths:
        full_url = urljoin(url, p)
        try:
            r = requests.get(full_url, timeout=5)
            content_lower = r.text.lower()

            if r.status_code == 200:
                found_keyword = False
                for k in vulnerable_keywords:
                    if k.lower() in content_lower:
                        if p == '/' and k.lower() in ['listing', 'directory']:
                            continue
                    found_keyword = True
                    break

                if found_keyword:
                    findings.append({
                        "name": f"Directory Listing at {p}",
                        "severity": "Warning",
                        "details": f"Response shows open directory at {full_url}.",
                        "owasp": owasp,
                        "rec": "Disable directory indexing in server config."
                    })
        except:
            pass

    if not findings:  # Always return something
        findings.append({
            "name": "Directory Listing Check",
            "severity": "OK",
            "details": "No open directories or default pages found on probed paths.",
            "owasp": owasp
        })

    return findings

# E: XSS check


def check_basic_xss(url):
    findings = []
    owasp = "A03:2021 - Injection (XSS)"
    parsed = urlparse(url)

    if not parsed.query:
        findings.append({
            "name": "XSS Check",
            "severity": "OK",
            "details": "No query parameters present to test for reflection.",
            "owasp": owasp,
            "rec": None
        })
        return findings

    payload = "<script>alert('xss')</script>"
    query_parts = parsed.query.split('&')
    any_vuln = False

    for part in query_parts:
        if "=" not in part:
            continue

        key = query_parts[0].split('=')[0]
        # Replace value of parameter with payload
        new_query = parsed.query.replace(part, f"{key}={payload}")
        new_url = parsed._replace(query=new_query).geturl()
        try:
            r = requests.get(new_url, timeout=5)
            if payload in r.text:
                findings.append({
                    "name": "Basic XSS Risk",
                    "severity": "Warning",
                    "details": "Payload reflected unescaped in response via parameter '{key}'.",
                    "owasp": owasp,
                    "rec": "Sanitize and encode user input before rendering in HTML."
                })
                any_vuln = True
        except:
            pass

    if not any_vuln and not findings:
        findings.append({
            "name": "XSS Check",
            "severity": "OK",
            "details": "No reflected payloads detected.",
            "owasp": owasp
        })

    return findings

# F: SQLi check


def check_basic_sqli(url):
    findings = []
    owasp = "A03:2021 - Injection"
    parsed = urlparse(url)

    if not parsed.query:
        findings.append({
            "name": "SQLi Check",
            "severity": "OK",
            "details": "No query parameters present to test for errors.",
            "owasp": owasp,
            "rec": None
        })
        return findings

    payloads = ["1'", "1 OR 1=1"]  # pay load
    query_parts = parsed.query.split('&')
    any_vuln = False

    for part in query_parts:
        if '=' not in part:
            continue
        key = part.split('=')[0]

        param_vuln = False
        for p in payloads:
            new_query = parsed.query.replace(part, f"{key}=1{p}")
            new_url = parsed._replace(query=new_query).geturl()

            try:
                r = requests.get(new_url, timeout=5)
                # Check for 500 error or common DB error messages
                if r.status_code == 500 or 'syntax error' in r.text.lower() or 'sql' in r.text.lower():
                    findings.append({
                        "name": f"SQLi Risk in Param '{key}'",
                        "severity": "Warning",
                        "details": f"Error signal received on payload '{p}' for parameter '{key}'.",
                        "owasp": owasp,
                        "rec": "Use prepared statements (parameterized queries)."
                    })
                    any_vuln = True
                    param_vuln = True
                    break  # Stop testing
            except:
                pass

    if not any_vuln and not findings:
        findings.append({
            "name": "SQLi Check",
            "severity": "OK",
            "details": "No error-based SQLi signals detected.",
            "owasp": owasp
        })
    return findings
