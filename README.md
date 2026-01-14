# Mini Web Vulnerability Scanner

A lightweight, Python-based web vulnerability scanner built with Flask. This tool was developed as a "Red Team" flavored project to demonstrate understanding of OWASP vulnerabilities, HTTP protocols, and Python.

Warning! This tool is for educational purposes only. Do not scan targets without explicit permission.

## Tech Stack

Python 3, Flask, Requests

## Prerequisites

Python 3.x installed.

## Setup and Use

1. Go to the project directory
2. Use bash to install dependencies: pip install -r requirements.txt
3. Use bash to run application: python app.py
4. Go to http://localhost:5000 in your browser
5. Enter the URL of the target (Do not scan targets without explicit permission)
6. Click Run Scan
7. The report will display findings categorized by severity

## Implemented Checks

I implemented checks for Security Headers (like CSP and X-Frame-Options), HTTPS and TLS usage, Server Fingerprinting, Directory Listing probing, Basic XSS reflection, and Basic SQL Injection errors.

## Development Challenges

The first problem was just getting the URL to pass to the checks.

Then I had to switch from having it print string outputs for the checks when I first made it to putting out dictionary outputs for the checks so the HTML report could read them.

Other things I learned or struggled with:
Setting up a Flask app from scratch.
Learning to def a function properly.
Struggling with GitHub trying to pull a past version when I broke the code.
Dealing with false positives with most checks (especially Directory Listing).
Figuring out how to make the info be shown nicely with HTML.

## Future Goals

[] 1. Separate get requests into each finding
[] 2. Research what the mutated get request should look like for each check
[] 3. Build out 2 mutated get requests for each finding into functions
