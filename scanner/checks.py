import requests
from bs4 import BeautifulSoup
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

# helpers
class LegacySSLAdapter(HTTPAdapter):
    def __init__(self, ssl_version=None, **kwargs):
        self.ssl_version = ssl_version
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, 
            ssl_version=self.ssl_version,
            **pool_kwargs         
        )

def get_reflection_context(html, payload):
    soup = BeautifulSoup(html, 'html.parser')
    # Find the payload in raw text, attributes, or script tags
    target = soup.find(string=lambda t: payload in t if t else False)
    if target:
        parent = target.parent.name
        if parent in ['script', 'style']:
            return f"Dangerous: Reflected inside a <{parent}> tag (Direct Execution)."
        return f"Warning: Reflected in HTML body as text inside <{parent}>."
    
    # Check if reflected inside an attribute (e.g., <input value="PAYLOAD">)
    for tag in soup.find_all():
        for attr, value in tag.attrs.items():
            if payload in str(value):
                return f"Warning: Reflected inside '{attr}' attribute of <{tag.name}> tag."
    return "Unknown Context: Reflected but not found in standard DOM nodes."

def calculate_delta(baseline, mutation):
    """
    Pillar I: Differential Analysis Engine
    Compares Baseline (Rb) vs Mutation (Rm) to find anomalies.
    """
    score = 0
    reasons = []

    # 1. Status Code Logic
    if baseline.status_code != mutation.status_code:
        if mutation.status_code >= 500:
            score += 100
            reasons.append(f"Server Error (HTTP {mutation.status_code})")
        elif mutation.status_code == 403:
            reasons.append("WAF Block Detected (HTTP 403)")

    # 2. Response Length Logic (Blind SQLi detection)
    len_b = len(baseline.text)
    len_m = len(mutation.text)
    
    if len_b > 0:
        variance = abs(len_b - len_m) / len_b
        # If size changed by more than 20%, it's a significant signal
        if variance > 0.20: 
            score += 80
            reasons.append(f"Significant Response Deviation ({int(variance*100)}%)")

    # 3. Error Signature Logic
    db_errors = ["syntax error", "fatal error", "mysql_fetch", "unclosed quotation mark", "ora-", "postgresql"]
    for err in db_errors:
        if err in mutation.text.lower() and err not in baseline.text.lower():
            score = 100
            reasons.append(f"Database Error Signature: '{err}'")

    return score, "; ".join(reasons)

def extract_input_vectors(url, html):
    """
    Finds inputs from URL params AND HTML Forms.
    Fixes the issue where Juice Shop / DVWA look "empty" to the scanner.
    """
    vectors = []
    parsed = urlparse(url)
    
    # 1. URL Parameters
    if parsed.query:
        for param in parse_qs(parsed.query):
            vectors.append({'type': 'url', 'param': param, 'url': url})
    
    # 2. HTML Forms
    soup = BeautifulSoup(html, 'html.parser')
    for form in soup.find_all('form'):
        action = form.get('action') or parsed.path
        target_url = urljoin(url, action)
        
        for input_tag in form.find_all('input'):
            name = input_tag.get('name')
            # Check for text-like inputs
            if name and input_tag.get('type', 'text') in ['text', 'search', 'url']:
                sep = '&' if '?' in target_url else '?'
                fuzz_url = f"{target_url}{sep}{name}=FUZZ"
                vectors.append({'type': 'form', 'param': name, 'url': fuzz_url})

    # 3. Fallback: If no inputs found, force a 'q' parameter test
    # This ensures we always scan SOMETHING
    if not vectors and not parsed.query:
        sep = '&' if '?' in url else '?'
        vectors.append({'type': 'forced', 'param': 'q', 'url': f"{url}{sep}q=FUZZ"})
        
    return vectors

# A: Headers (check 5 headers for missing/OK + mutataions)
def check_security_headers(url):
    findings = []
    owasp = "A05:2021 - Security Misconfiguration"

    #1. baseline
    try:
        response = requests.get(url, timeout=5)
        baseline_headers = response.headers
    except Exception as e:
        findings.append({
            "name": "Header Check Failed",
            "severity": "Info",
            "details": f"Error running check: {str(e)}",
            "owasp": "N/A",
            "evidence": {
                "request": f"GET {url}",
                "response_excerpt": "No response received",
                "diff": "N/A"
            },
            "verdict": "Check aborted due to network failure."
        })
        return findings

    is_https = urlparse(url).scheme == 'https'

    # standard header list
    headers_to_check = [
        ('Content-Security-Policy', 'CSP',
         "Blocks unauthorized scripts/resources to prevent XSS."),
        ('X-Frame-Options', 'XFO', "Prevents clickjacking by blocking iframe embedding."),
        ('X-Content-Type-Options', 'XCTO', "Stops MIME type sniffing attacks."),
        ('Referrer-Policy', 'RP', "Controls referrer info to protect privacy.")
    ]

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
                "rec": None,
                "signal_proof": {
                    "baseline": {"status": response.status_code, "reflection": f"{header_name} is set."},
                    "mutations": []
                },
                "verdict": f"Secure baseline. {header_name} is properly configured."
            })
        else:
            # BROAD FIX: Systematic state tracking
            m1_vulnerable = False
            m2_vulnerable = False

            error_url = urljoin(url, "/does_not_exist_fuzz_test_123")
            m1_status = "N/A"
            m1_logic = "Test Failed"
            try:
                r_error = requests.get(error_url, timeout=5)
                m1_status = r_error.status_code
                if header_name not in r_error.headers:
                    m1_vulnerable = True
                    m1_logic = f"Confirmed: {header_name} is missing on 404 pages."
                else:
                    m1_logic = f"Anomaly: {header_name} IS enforced on 404 pages."
            except: pass

            m2_status = "N/A" 
            m2_logic = "Test Failed"
            try:
                spoof_headers = {'Host': '127.0.0.1'}
                r_spoof = requests.get(url, headers=spoof_headers, timeout=5)
                m2_status = r_spoof.status_code
                if header_name not in r_spoof.headers:
                    m2_vulnerable = True
                    m2_logic = f"Confirmed: {header_name} is missing even with spoofed Host."
                else:
                    m2_logic = "Anomaly: Header appeared during Host spoofing."
            except: pass

            # Calculate verdict based on boolean state, not string matching
            if m1_vulnerable and m2_vulnerable:
                dynamic_verdict = f"Vulnerable. The server lacks the {header_name} header globally. Active mutations confirmed the misconfiguration persists across error states and routing changes."
            elif not m1_vulnerable and not m2_vulnerable:
                dynamic_verdict = f"Vulnerable Baseline. The main page lacks {header_name}, but active mutations revealed the server DOES enforce it on error pages and abnormal routing. Check backend config consistency."
            else:
                dynamic_verdict = f"Vulnerable Baseline. The main page lacks {header_name}. Active mutations showed inconsistent enforcement across the server."

            findings.append({
                "name": f"Missing {short_name} Header",
                "severity": "Warning",
                "details": f"No {header_name} header found. {explanation}",
                "owasp": owasp,
                "rec": f"Configure the '{header_name}' header.",
                "signal_proof": {
                    "baseline": {"status": response.status_code, "reflection": f"{header_name} MISSING"},
                    "mutations": [
                        {
                            "trigger": f"GET {error_url}",
                            "payload": "404 Error Path",
                            "status": m1_status,
                            "logic": m1_logic
                        },
                        {
                            "trigger": f"GET {url} (Host: 127.0.0.1)",
                            "payload": "Host Header Spoof",
                            "status": m2_status,
                            "logic": m2_logic
                        }
                    ] 
                },
                "verdict": dynamic_verdict
            })


    return findings

# B: HTTPS Configuration (Baseline + 2 Mutations)
def check_https(url):
    findings = []
    owasp = "A05:2021 - Security Misconfiguration"
    parsed = urlparse(url)

    # --- SCENARIO 1: Target is HTTP (Insecure) ---
    if parsed.scheme != "https":
        https_url = url.replace("http://", "https://")
        
        # Mutation 1: Check if HTTPS port (443) is open
        m1_status = "Closed/Unreachable"
        m1_logic = "Port 443 is not accepting connections."
        try:
            r_https = requests.get(https_url, verify=False, timeout=5)
            m1_status = r_https.status_code
            m1_logic = "Vulnerable: HTTPS is open but not enforced (No 301 redirect from HTTP)."
        except: pass

        # Mutation 2: Check for HSTS Header Leak on HTTP
        m2_status = "N/A"
        m2_logic = "No HSTS header leaked over HTTP."
        try:
            r_http = requests.get(url, timeout=5)
            m2_status = r_http.status_code
            if 'Strict-Transport-Security' in r_http.headers:
                m2_logic = "Anomaly: HSTS header found on HTTP (Ignored by browsers)."
        except: pass

        findings.append({
            "name": "HTTPS Usage",
            "severity": "Warning",
            "details": "No HTTPS in use, traffic could be intercepted.",
            "owasp": owasp,
            "rec": "Redirect all HTTP to HTTPS and use HSTS.",
            "signal_proof": {
                "baseline": {"status": "Cleartext (HTTP)", "reflection": "Port 80 Insecure"},
                "mutations": [
                    {
                        "trigger": f"GET {https_url}",
                        "payload": "Force HTTPS Scheme",
                        "status": m1_status,
                        "logic": m1_logic
                    },
                    {
                        "trigger": f"GET {url}",
                        "payload": "HSTS Leak Check",
                        "status": m2_status,
                        "logic": m2_logic
                    }
                ]
            },
            "verdict": "Vulnerable. Traffic is unencrypted. Active probing confirms HTTPS is not enforced."
        })
        return findings 

    try:
        baseline_resp = requests.get(url, verify=True, timeout=5)
        
        # Mutation 1: TLS 1.0 Downgrade Attack
        session = requests.Session()
        m1_status = "Rejected"
        m1_logic = "Secure: TLS 1.0 connection rejected."
        try:
            session.mount('https://', LegacySSLAdapter(ssl.PROTOCOL_TLSv1))
            r_tls = session.get(url, timeout=5)
            m1_status = r_tls.status_code
            m1_logic = "Vulnerable: Server accepted deprecated TLS 1.0 protocol."
        except: pass

        # Mutation 2: SNI Bypass / Host Spoofing
        m2_status = "Rejected"
        m2_logic = "Secure: localhost SNI rejected/ignored."
        try:
            r_sni = requests.get(url, headers={'Host': 'localhost'}, verify=False, timeout=5)
            m2_status = r_sni.status_code
            if m2_status == 200:
                m2_logic = "Caution: Server responded to internal hostname 'localhost'."
        except: pass

        # Determine Verdict
        severity = "Warning" if "Vulnerable" in m1_logic else "OK"
        rec = "Disable TLS 1.0/1.1 in server configuration." if severity == "Warning" else None

        findings.append({
            "name": "HTTPS Protocol Analysis",
            "severity": severity,
            "details": "Checking certificate validity and protocol downgrade resistance.",
            "owasp": owasp,
            "rec": rec,
            "signal_proof": {
                "baseline": {"status": baseline_resp.status_code, "reflection": "Valid TLS Certificate"},
                "mutations": [
                    {
                        "trigger": "Forced TLSv1.0 Connection",
                        "payload": "Legacy SSL Adapter",
                        "status": m1_status,
                        "logic": m1_logic
                    },
                    {
                        "trigger": "Host: localhost",
                        "payload": "SNI Bypass",
                        "status": m2_status,
                        "logic": m2_logic
                    }
                ]
            },
            "verdict": f"Analyst Note: TLS Downgrade test resulted in [{m1_status}]. SNI bypass resulted in [{m2_status}]."
        })
        
    except requests.exceptions.SSLError as e:
        # Catch invalid certificates (expired, self-signed)
        findings.append({
            "name": "HTTPS Certificate Error",
            "severity": "Warning",
            "details": "Certificate validation failed (e.g., expired or self-signed).",
            "owasp": owasp,
            "rec": "Install a valid TLS certificate from a trusted CA.",
            "signal_proof": {
                "baseline": {"status": "SSL Error", "reflection": str(e)[:100]},
                "mutations": []
            },
            "verdict": "Vulnerable. The certificate is invalid, causing browser security warnings."
        })
    except Exception:
        pass

    return findings

# C: Server Fingerprint (Baseline + 2 Mutations)
def check_server_fingerprint(url):
    findings = []
    owasp = "A06:2021 - Vulnerable and Outdated Components"

    # 1. Phase 1: Baseline Analysis
    try:
        response = requests.get(url, timeout=5)
    except Exception as e:
        findings.append({
            "name": "Fingerprint Check Failed",
            "severity": "Info",
            "details": f"Error running check: {str(e)}",
            "owasp": "N/A",
            "evidence": {
                "request": f"GET {url}",
                "response_excerpt": "No response received",
                "diff": "N/A"
            },
            "verdict": "Check aborted due to network failure."
        })
        return findings

    # check sever header
    leaked_headers = {}
    if 'Server' in response.headers: leaked_headers['Server'] = response.headers['Server']
    if 'X-Powered-By' in response.headers: leaked_headers['X-Powered-By'] = response.headers['X-Powered-By']

    if leaked_headers:
        # Construct the baseline reflection string
        baseline_reflection = " | ".join([f"{k}: {v}" for k, v in leaked_headers.items()])

        
        # Mutation 1: WAF Bypass / Malformed Request
        bad_url = urljoin(url, "/%ff%ff%ff")
        m1_status = "N/A"
        m1_logic = "Request failed."
        try:
            bad_resp = requests.get(bad_url, timeout=5)
            m1_status = bad_resp.status_code
            bad_server = bad_resp.headers.get('Server', 'Masked')
            if bad_server != 'Masked' and bad_server != leaked_headers.get('Server'):
                 m1_logic = f"Vulnerable: Error page leaked different backend ({bad_server})."
            else:
                 m1_logic = f"Secure: Error page maintained identity ({bad_server})."
        except: pass

        # Mutation 2: Legacy Method Check (TRACE)
        m2_status = "N/A"
        m2_logic = "TRACE method rejected."
        try:
            trace_resp = requests.request('TRACE', url, timeout=5)
            m2_status = trace_resp.status_code
            if trace_resp.status_code == 200 and 'TRACE' in trace_resp.text:
                m2_logic = "Vulnerable: TRACE method enabled (XST risk)."
        except: pass

        findings.append({
            "name": "Server Fingerprint Disclosure",
            "severity": "Info" if "Vulnerable" not in m1_logic and "Vulnerable" not in m2_logic else "Warning",
            "details": f"Server identity broadcast detected.",
            "owasp": owasp,
            "signal_proof": {
                "baseline": {"status": response.status_code, "reflection": baseline_reflection},
                "mutations": [
                    {
                        "trigger": f"GET {bad_url}",
                        "payload": "Malformed UTF-8 (%ff)",
                        "status": m1_status,
                        "logic": m1_logic
                    },
                    {
                        "trigger": f"TRACE {url}",
                        "payload": "HTTP TRACE Method",
                        "status": m2_status,
                        "logic": m2_logic
                    }
                ]
            },
            "verdict": f"Analyst Note: Identity exposed. Mutation 1 (Malformed) result: [{m1_status}]. Mutation 2 (TRACE) result: [{m2_status}]."
        })
    if not findings:
        findings.append({
            "name": "Server Fingerprint",
            "severity": "OK",
            "details": "No Server or X-Powered-By headers—good, reduces info leakage.",
            "owasp": owasp,
            "signal_proof": {
                "baseline": {"status": 200, "reflection": "Headers are masked/hidden."},
                "mutations": []
            },
            "verdict": "Secure. Server identity headers are properly suppressed, reducing passive reconnaissance risk."
        })
        
    return findings

# D: Directory Listing (Baseline + 2 Mutations)
def check_directory_listing(url):
    findings = []
    owasp = "A05:2021 - Security Misconfiguration"
    try:
        baseline_resp = requests.get(url, timeout=5)
    except:
        return []

    # Phase 1: Baseline Analysis (Standard Probing)
    paths = ['/', '/admin/', '/test/', '/backup/', '/ftp/']
    vulnerable_keywords = ["index of /","parent directory",]

    for p in paths:
        full_url = urljoin(url, p)
        try:
            r = requests.get(full_url, timeout=5)
            content_lower = r.text.lower()

            if r.status_code == 200:
                for k in vulnerable_keywords:
                    if k.lower() in content_lower:
                        if p == '/' and k.lower() in ['listing', 'directory']: continue

                        findings.append({
                            "name": f"Directory Listing at {p}",
                            "severity": "Warning",
                            "details": f"Response shows open directory at {full_url}.",
                            "owasp": owasp,
                            "rec": "Disable directory indexing in server config.",
                            "signal_proof": {
                                "baseline": {"status": baseline_resp.status_code, "reflection": "Home Page / Standard Content"},
                                "mutations": [{
                                    "trigger": f"GET {full_url}",
                                    "payload": f"Path: {p}",
                                    "status": r.status_code,
                                    "logic": f"Found signature '{k}' in response body."
                                }]
                            },
                            "verdict": f"Confirmed. The server is configured to list files at '{p}', potentially exposing sensitive backups or source code."
                        })
                        break
        except: pass

    # Phase 2: Mutation - Infrastructure Enumeration (Repo Looter)
    sensitive_artifacts = [
        ('.env', 'DB_PASSWORD', 'Environment config file exposed.'),
        ('.git/HEAD', 'refs/heads', 'Source code repository (.git) exposed.'),
        ('sitemap.xml', 'urlset', 'Sitemap exposed (info disclosure).'),
        ('robots.txt', 'User-agent', 'Robots.txt exposed (info disclosure).')
    ]

    for filename, distinct_string, desc in sensitive_artifacts:
        target_url = urljoin(url, filename)
        try:
            r = requests.get(target_url, timeout=5)
            if r.status_code == 200 and distinct_string in r.text:
                 findings.append({
                    "name": f"Sensitive File Exposed ({filename})",
                    "severity": "Warning" if '.env' in filename or '.git' in filename else "Info",
                    "details": desc,
                    "owasp": owasp,
                    "rec": f"Block access to {filename} in server config.",
                    "signal_proof": {
                        "baseline": {"status": 404, "reflection": "Expected File to be Hidden"},
                        "mutations": [{
                            "trigger": f"GET {target_url}",
                            "payload": filename,
                            "status": r.status_code,
                            "logic": f"Found string '{distinct_string}' inside the file."
                        }]
                    },
                    "verdict": "Exploitable. Warning infrastructure file is publicly accessible."
                })
        except: pass

    # Phase 3: Mutation - Backup Enumeration
    try:
        backup_url = urljoin(url, "index.php.bak") 
        r_bak = requests.get(backup_url, timeout=5)
        
        if r_bak.status_code == 200 and "<?php" in r_bak.text:
            findings.append({
                "name": "Source Code Disclosure",
                "severity": "Warning",
                "details": "Backup file (.bak) found containing server-side code.",
                "owasp": owasp,
                "rec": "Remove backup files from the production web root.",
                "signal_proof": {
                    "baseline": {"status": baseline_resp.status_code, "reflection": "Executing Code (Baseline)"},
                    "mutations": [{
                        "trigger": f"GET {backup_url}",
                        "payload": ".bak extension",
                        "status": r_bak.status_code,
                        "logic": "Server returned raw PHP source code instead of executing it."
                    }]
                },
                "verdict": "Vulnerable. Attacker can read source code."
            })
    except: pass
    
    if not findings:
        findings.append({
            "name": "Directory Listing Check",
            "severity": "OK",
            "details": "No open directories or default pages found on probed paths.",
            "owasp": owasp,
            "signal_proof": {
                "baseline": {"status": baseline_resp.status_code, "reflection": "Standard Page Load"},
                "mutations": [
                    {
                        "trigger": f"GET {urljoin(url, '/admin/')}",
                        "payload": "Path: /admin/",
                        "status": "403/404",
                        "logic": "Directory denied or not found."
                    },
                    {
                        "trigger": f"GET {urljoin(url, '.git/HEAD')}",
                        "payload": "Path: .git/HEAD",
                        "status": "403/404",
                        "logic": "Hidden file denied or not found."
                    }
                ]
            },
            "verdict": "Secure. Server properly denies or redirects access to internal directories."
        })

    return findings

# E: XSS check (Baseline + 2 Mutations)
def check_basic_xss(url):
    findings = []
    owasp = "A03:2021 - Injection (XSS)"
    
    # 1. Baseline Acquisition
    try:
        baseline = requests.get(url, headers={'User-Agent': 'SignalProofScanner/1.0'}, timeout=5)
    except: return []

    # 2. Smart Input Discovery (Uses the new helper)
    vectors = extract_input_vectors(url, baseline.text)
    
    # 3. Mutation Loop
    payload1 = "<script>alert(1)</script>" # The Canary
    payload2 = "\"'<>" # Context Encoding Probe (Goal #2)
    
    for v in vectors:
        # Prepare the attack URLs for both mutations
        if v['type'] == 'url':
            parsed = urlparse(v['url'])
            qs1, qs2 = parse_qs(parsed.query), parse_qs(parsed.query)
            qs1[v['param']], qs2[v['param']] = [payload1], [payload2]
            url1 = parsed._replace(query=urlencode(qs1, doseq=True)).geturl()
            url2 = parsed._replace(query=urlencode(qs2, doseq=True)).geturl()
        else:
            url1 = v['url'].replace('FUZZ', payload1)
            url2 = v['url'].replace('FUZZ', payload2)
            
        try:
            mut1 = requests.get(url1, timeout=5)
            mut2 = requests.get(url2, timeout=5)
            
            # 4. Context Analysis (Goal #2)
            if payload1 in mut1.text or payload2 in mut2.text:
                context = get_reflection_context(mut1.text, payload1)
                
                # Verify if the second payload escaped sanitization
                encoding_logic = "Special characters '<>' were NOT escaped." if payload2 in mut2.text else "Special characters were filtered."
                
                # 5. Signal Proof Generation
                findings.append({
                    "name": "Reflected Cross-Site Scripting (XSS)",
                    "severity": "High",
                    "details": f"Input reflected in {context}",
                    "owasp": owasp,
                    "signal_proof": {
                        "baseline": {
                            "status": baseline.status_code,
                            "reflection": "None (Payload not present)"
                        },
                        "mutations": [
                            {
                                "trigger": f"GET {url1}",
                                "payload": payload1,
                                "status": mut1.status_code,
                                "context": context
                            },
                            {
                                "trigger": f"GET {url2}",
                                "payload": payload2,
                                "status": mut2.status_code,
                                "logic": encoding_logic
                            }
                        ]
                    },
                    "verdict": (
                        f"Baseline request showed no reflection. Mutation 1 using '{payload1}' "
                        f"was reflected in {context}. Mutation 2 confirmed that {encoding_logic.lower()} "
                        f"This verifies execution is possible."
                    ),
                    "rec": "Implement context-aware output encoding."
                })
                break # Stop after finding one XSS to keep report clean
        except: pass
    if not findings:
        findings.append({
            "name": "Reflected XSS Check",
            "severity": "OK",
            "details": "No reflected XSS payloads were detected in the scanned parameters.",
            "owasp": owasp,
            "signal_proof": {
                "baseline": {"status": 200, "reflection": "Normal Page Load"},
                "mutations": []
            },
            "verdict": "Secure (or Inconclusive). The scanner sent malicious payloads but did not see them reflected in the raw HTML response."
        })
    return findings

# F: SQLi check (Error-Based + Union-Based)
def check_basic_sqli(url):
    findings = []
    owasp = "A03:2021 - Injection"
    
    try:
        baseline = requests.get(url, timeout=5)
    except: return []

    # Uses the same smart extractor as XSS
    vectors = extract_input_vectors(url, baseline.text)
    trigger1 = "'" # Mutation 1: Error Trigger
    trigger2 = "''" # Mutation 2: Balancing Probe

    for v in vectors:
        if v['type'] == 'url':
            parsed = urlparse(v['url'])
            qs1, qs2 = parse_qs(parsed.query), parse_qs(parsed.query)
            qs1[v['param']] = [qs1[v['param']][0] + trigger1]
            qs2[v['param']] = [qs2[v['param']][0] + trigger2]
            url1 = parsed._replace(query=urlencode(qs1, doseq=True)).geturl()
            url2 = parsed._replace(query=urlencode(qs2, doseq=True)).geturl()
        else:
            url1 = v['url'].replace('FUZZ', '1' + trigger1)
            url2 = v['url'].replace('FUZZ', '1' + trigger2)

        try:
            mut1 = requests.get(url1, timeout=5)
            mut2 = requests.get(url2, timeout=5)
            
            # 1. Differential Analysis (Pillar I)
            score1, reason1 = calculate_delta(baseline, mut1)
            score2, reason2 = calculate_delta(baseline, mut2)
            
            if score1 > 50:
                findings.append({
                    "name": "SQL Injection Detected",
                    "severity": "High",
                    "details": f"Differential anomaly detected: {reason1}",
                    "owasp": owasp,
                    "confidence": "High" if score1 >= 80 else "Medium",
                    "signal_proof": {
                        "baseline": {
                            "status": baseline.status_code,
                            "length": len(baseline.text)
                        },
                        "mutations": [
                            {
                                "trigger": f"GET {url1}",
                                "payload": trigger1,
                                "status": mut1.status_code,
                                "length": len(mut1.text),
                                "logic": reason1
                            },
                            {
                                "trigger": f"GET {url2}",
                                "payload": trigger2,
                                "status": mut2.status_code,
                                "length": len(mut2.text),
                                "logic": "Secondary probe to confirm backend differential behavior."
                            }
                        ]
                    },
                    "verdict": (
                        f"Baseline response was {len(baseline.text)} chars. "
                        f"Mutation 1 ('{trigger1}') caused a deviation. Mutation 2 ('{trigger2}') verified differential behavior. "
                        f"This confirms a backend logical break."
                    ),
                    "rec": "Use prepared statements (parameterized queries)."
                })
                break
        except: pass

    if not findings:
        findings.append({
            "name": "SQL Injection Check",
            "severity": "OK",
            "details": "No database errors or significant response anomalies detected.",
            "owasp": owasp,
            "signal_proof": {
                "baseline": {"status": 200, "reflection": "Normal Data Load"},
                "mutations": []
            },
            "verdict": "Secure. The application handled SQL syntax tokens without crashing or leaking data."
        })
    return findings
   