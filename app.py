# Flask for app, render for HTML, request for form data
from flask import Flask, render_template, request
import requests  # For getting the page response (spec A needs headers)
from scanner import *  # Grabs my 6 checks (easy wildcard)

app = Flask(__name__)  # Makes the app


@app.route('/')
def home():
    return render_template('index.html')  # Shows the form page


@app.route('/scan', methods=['GET', 'POST'])  # Handles /scan GET or POST
def scan():
    if request.method == 'POST':  # If form submitted.
        url = request.form.get('url')  # Gets the URL from the input box
        # List to hold all check results (guide says collect them)
        all_findings = []
        try:
            # Gets the page (spec A "Send a GET request")
            response = requests.get(url, timeout=5)
        except:
            # If bad URL, add note
            all_findings.append("Error: Can't reach URL")
            response = None  # No response for headers checks
        if response:  # If GET worked
            # A: Headers
            # Calls A (needs url for HSTS)
            headers_results = check_security_headers(response, url)
            all_findings += headers_results
            # C: Fingerprint
            # Calls C (headers)
            fingerprint_results = check_server_fingerprint(response)
            all_findings += fingerprint_results
        # D: Dir Listing
        dir_results = check_directory_listing(url)  # Calls D (url for paths)
        all_findings += dir_results
        # B: HTTPS
        https_results = check_https(url)  # Calls B (url scheme)
        all_findings += https_results
        # E: XSS
        xss_results = check_basic_xss(url)  # Calls E (url params)
        all_findings += xss_results
        # F: SQLi
        sqli_results = check_basic_sqli(url)  # Calls F (url params)
        all_findings += sqli_results
        # Pass URL + results to report.
        return render_template('report.html', target_url=url, findings=all_findings)
    return 'Use the form on home page'  # If not POST, show message


if __name__ == "__main__":
    # Runs the app on port 5000, debug shows errors
    app.run(host="0.0.0.0", port=5000, debug=True)
