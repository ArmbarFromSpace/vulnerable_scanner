from flask import Flask, render_template, request
import requests
from scanner.checks import *
from datetime import datetime

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        url = request.form.get('url')

        if not url:
            return "Please provide a valid URL.", 400

        if url and not url.startswith('http'):
            url = 'http://' + url

        # Normalize URL trailing slash
        if not url.endswith('/'):
            url = url + '/'

        all_findings = []
        http_status = 'N/A'

        try:
            ping = requests.get(url, timeout=5, verify=True, headers={'User-Agent': 'SignalProofScanner/1.0'})
            http_status = ping.status_code
        except:
            all_findings.append({
                "name": "Page Accessibility",
                "severity": "info",
                "details": "Error: can't reach URL",
                "owasp": "N/A",
                "rec": None
            })
            # If dead, just return immediately
            context = {
                'target_url': url, 
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'http_status': 'Error',
                'findings': all_findings,
                'total_checks': 0, 'warnings': 0, 'info': 0, 'oks': 0
            }
            return render_template('report.html', **context)

        all_findings.extend(check_security_headers(url) or [])
        all_findings.extend(check_https(url) or [])
        all_findings.extend(check_server_fingerprint(url) or [])
        all_findings.extend(check_directory_listing(url) or [])
        all_findings.extend(check_basic_xss(url) or [])
        all_findings.extend(check_basic_sqli(url) or [])

        groups = {
            "Header Analysis": [],
            "HTTPS Configuration": [],
            "Server Fingerprinting": [],
            "Directory Listing": [],
            "Reflected XSS": [],
            "SQL Injection": []
        }

        # Sort every finding into the right bucket
        for f in all_findings:
            name = f['name'].lower()
            
            # Match keywords to categories
            if 'header' in name or 'routing bypass' in name or 'weak security' in name:
                groups['Header Analysis'].append(f)
            elif 'https' in name or 'ssl' in name or 'encryption' in name:
                groups['HTTPS Configuration'].append(f)
            elif 'powered-by' in name or 'fingerprint' in name:
                groups['Server Fingerprinting'].append(f)
            elif 'directory' in name or 'file' in name or 'source code' in name or 'listing' in name:
                groups['Directory Listing'].append(f)
            elif 'xss' in name:
                groups['Reflected XSS'].append(f)
            elif 'sql' in name:
                groups['SQL Injection'].append(f)
            else:
                # Fallback: Put weird/unknown findings in Headers so they aren't lost
                groups['Header Analysis'].append(f)

        # 4. Prepare the Final Rows for HTML
        final_rows = []
        for category, items in groups.items():
            # Calculate the "Worst" severity in this group to color the row
            row_severity = "OK"
            if any(i['severity'].lower() == 'high' for i in items):
                row_severity = "High"
            elif any(i['severity'].lower() == 'warning' for i in items):
                row_severity = "Warning"
            elif any(i['severity'].lower() == 'info' for i in items):
                if row_severity == "OK": row_severity = "Info"
            
            # Grab the OWASP mapping from the first item (if exists)
            owasp = items[0]['owasp'] if items else "N/A"

            final_rows.append({
                "category": category,
                "severity": row_severity,
                "items": items,
                "owasp": owasp
            })

        # summarires
        total_checks = len(all_findings)
        count_Warnings = len( [f for f in all_findings if f['severity'] == 'Warning'])
        count_infos = len([f for f in all_findings if f['severity'] == 'info'])
        count_ok = len([f for f in all_findings if f['severity'] == 'OK'])

        context = {
            'target_url': url,
            'scan_time': datetime.now().strftime('%Y-%m%d %H:%M:%S'),
            'http_status': http_status,
            'total_checks': total_checks,
            'warnings': count_Warnings,
            'info': count_infos,
            'oks': count_ok,
            'grouped_findings': final_rows
        }

        return render_template('report.html', **context)
    
    return 'Use the form on home page'  

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
