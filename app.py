from flask import Flask, render_template, request
import requests  # For getting the page response
from scanner.checks import *
from datetime import datetime

app = Flask(__name__)  # Makes the app


@app.route('/')
def home():
    return render_template('index.html')  # Shows the form page


@app.route('/scan', methods=['GET', 'POST'])  # Handles /scan GET or POST
def scan():
    if request.method == 'POST':  # If form submitted.
        url = request.form.get('url')  # Gets the URL from the input box

        if not url:
            return "Please provide a valid URL.", 400

        if url and not url.startswith('http'):
            url = 'http://' + url

        if not url.endswith('/'):
            url = url + '/'

        all_findings = []
        http_status = 'N/A'
        response = None

        try:
            ping = requests.get(url, timeout=5, verify=True)
            http_status = ping.status_code
        except:
            # If bad URL, add note
            all_findings.append({
                "name": "Page Accessibility",
                "severity": "info",
                "details": "Error: can't reach URL",
                "owasp": "N/A",
                "rec": None
            })
            context = {
                'target_url': url, 'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'http_status': 'Error', 'findings': all_findings,
                'total_checks': 0, 'warnings': 0, 'info': 0, 'oks': 0
            }
            return render_template('report.html', **context)

        # A: Headers
        headers_results = check_security_headers(url)
        all_findings += headers_results
        # C: Fingerprint
        fingerprint_results = check_server_fingerprint(url)
        all_findings += fingerprint_results
        # D: Dir Listing
        dir_results = check_directory_listing(url)
        all_findings += dir_results
        # B: HTTPSrrr
        https_results = check_https(url)
        all_findings += https_results
        # E: XSS
        xss_results = check_basic_xss(url)
        all_findings += xss_results
        # F: SQLi
        sqli_results = check_basic_sqli(url)
        all_findings += sqli_results

        # summarires
        total_checks = len(all_findings)
        count_Warnings = len(
            [f for f in all_findings if f['severity'] == 'Warning'])
        count_infos = len([f for f in all_findings if f['severity'] == 'info'])
        count_oks = len([f for f in all_findings if f['severity'] == 'OK'])

        context = {
            'target_url': url,
            'scan_time': datetime.now().strftime('%Y-%m%d %H:%M:%S'),
            'http_status': http_status,
            'total_checks': total_checks,
            'warnings': count_Warnings,
            'info': count_infos,
            'oks': count_oks,
            'findings': all_findings
        }

        # Pass URL + results to report.
        return render_template('report.html', **context)
    return 'Use the form on home page'  # If not POST, show message


if __name__ == "__main__":
    # Runs the app on port 5000, debug shows errors
    app.run(host="0.0.0.0", port=5000, debug=True)
