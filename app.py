from flask import Flask, request, render_template
import requests
from bs4 import BeautifulSoup
import re
import pandas as pd

app = Flask(__name__)

# Load the dataset once when app starts
df = pd.read_csv("vulnerability_fix_dataset.csv")

def get_fix(vuln_type):
    match = df[df['vulnerability_type'].str.lower() == vuln_type.lower()]
    if not match.empty:
        return match.iloc[0]['vulnerable_code'], match.iloc[0]['fixed_code']
    return "N/A", "N/A"

def scan_website(url):
    result = []

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')

        # XSS
        forms = soup.find_all('form')
        for form in forms:
            if "onsubmit" not in form.attrs:
                vuln_code, fix_code = get_fix("Cross-Site Scripting")
                result.append(("Cross-Site Scripting", "Form without validation found.", vuln_code, fix_code))

        # Missing Headers
        if 'X-Content-Type-Options' not in response.headers:
            vuln_code, fix_code = get_fix("Missing Security Header")
            result.append(("Missing Security Header", "X-Content-Type-Options is missing.", vuln_code, fix_code))

        if 'Content-Security-Policy' not in response.headers:
            vuln_code, fix_code = get_fix("Missing CSP")
            result.append(("Missing CSP", "CSP header is missing.", vuln_code, fix_code))

        # Clickjacking
        if 'X-Frame-Options' not in response.headers:
            vuln_code, fix_code = get_fix("Clickjacking")
            result.append(("Clickjacking", "X-Frame-Options header is missing.", vuln_code, fix_code))

        # Directory Listing
        if re.search(r"Index of /", html):
            vuln_code, fix_code = get_fix("Directory Listing")
            result.append(("Directory Listing", "Open directory listing found.", vuln_code, fix_code))

        # SQL Injection (basic)
        if "?" in url:
            test_url = url + "'"
            test_response = requests.get(test_url)
            if "SQL syntax" in test_response.text or "mysql_fetch" in test_response.text:
                vuln_code, fix_code = get_fix("SQL Injection")
                result.append(("SQL Injection", "Possible SQL injection point detected.", vuln_code, fix_code))

        if not result:
            result.append(("Secure", "No common vulnerabilities found.", "", ""))

    except Exception as e:
        result.append(("Error", str(e), "", ""))

    return result

@app.route('/', methods=['GET', 'POST'])
def index():
    vulnerabilities = []
    if request.method == 'POST':
        website = request.form['website']
        if not website.startswith("http"):
            website = "http://" + website
        vulnerabilities = scan_website(website)
    return render_template('index.html', vulnerabilities=vulnerabilities)

if __name__ == '__main__':
    app.run(debug=True)
