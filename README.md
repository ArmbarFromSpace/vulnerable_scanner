# Mini Web Vulnerability Scanner

A lightweight, Python-based web vulnerability scanner built with Flask. This tool was developed as a "Red Team" flavored project to demonstrate understanding of OWASP vulnerabilities, HTTP protocols, and Python.

Warning! This tool is for educational purposes only. Do not scan targets without explicit permission.

## Tech Stack

Python 3, Flask, Requests, BeautifulSoup4

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

I implemented active mutation checks for Security Headers (404 fuzzing and Host spoofing), HTTPS/TLS usage (TLS 1.0 downgrades and SNI bypasses), Server Fingerprinting (malformed UTF-8 and TRACE methods), Directory Listing (sensitive file and backup probing), XSS reflection (canary and encoding probes), and SQL Injection (error and balancing triggers).

## Development Challenges

Building this version was a major learning curve as I moved away from simple requests. I researched and implemented specific attacks like Host Header Spoofing, 404 Fuzzing, TLS Downgrades, and Malformed UTF-8 (%ff), which required refactoring the entire codebase into a nested dictionary structure. The hardest part was writing the logic to compare the Baseline against Mutations to detect differences in status codes and response lengths. I also updated the HTML boxes that show the exact payload and evidence, though I still struggled with the logic for Checks D, E, and F and they still dont fully work.

## Future Goals

at this point I cant think of more goals beside
ADD a abilty to re do checks independetly
