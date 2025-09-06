from flask import Flask, request, render_template, redirect, url_for, session
import requests
from bs4 import BeautifulSoup
import re
import pandas as pd
import matplotlib.pyplot as plt
import os
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
import json

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Load vulnerability fix dataset
df = pd.read_csv("vulnerability_fix_dataset.csv")

# Dummy user store (replace with DB in production)
users = {}

# Ensure result_data file exists
if not os.path.exists("C:/Users/khale/OneDrive/Desktop/simple scanner/result_data.xlsx"):
    pd.DataFrame(columns=["username", "website", "vulnerability", "description"]).to_excel("result_data.xlsx", index=False)

if not os.path.exists("feedback.txt"):
    with open("feedback.txt", "w") as f:
        f.write("")

# URL validator
def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

# Fetch fix info from CSV
def get_fix(vuln_type):
    match = df[df['vulnerability_type'].str.lower() == vuln_type.lower()]
    if not match.empty:
        return match.iloc[0]['vulnerable_code'], match.iloc[0]['fixed_code']
    return "N/A", "N/A"

# Scanner
def scan_website(url):
    result = []
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')

        forms = soup.find_all('form')
        for form in forms:
            if "onsubmit" not in form.attrs:
                vuln_code, fix_code = get_fix("Cross-Site Scripting")
                result.append(("Cross-Site Scripting", "Form without validation found.", vuln_code, fix_code))

        if 'X-Content-Type-Options' not in response.headers:
            vuln_code, fix_code = get_fix("Missing Security Header")
            result.append(("Missing Security Header", "X-Content-Type-Options is missing.", vuln_code, fix_code))

        if 'Content-Security-Policy' not in response.headers:
            vuln_code, fix_code = get_fix("Missing CSP")
            result.append(("Missing CSP", "CSP header is missing.", vuln_code, fix_code))

        if 'X-Frame-Options' not in response.headers:
            vuln_code, fix_code = get_fix("Clickjacking")
            result.append(("Clickjacking", "X-Frame-Options header is missing.", vuln_code, fix_code))

        if re.search(r"Index of /", html):
            vuln_code, fix_code = get_fix("Directory Listing")
            result.append(("Directory Listing", "Open directory listing found.", vuln_code, fix_code))

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

# Home
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'username' not in session:
        return redirect(url_for('login'))

    vulnerabilities = []
    if request.method == 'POST':
        website = request.form['website']
        if not website.startswith("http"):
            website = "http://" + website
        if is_valid_url(website):
            vulnerabilities = scan_website(website)

            df_result = pd.read_excel("result_data.xlsx")
            for v in vulnerabilities:
                df_result.loc[len(df_result)] = [session['username'], website, v[0], v[1]]
            df_result.to_excel("result_data.xlsx", index=False)
        else:
            vulnerabilities = [("Error", "Invalid URL provided", "", "")]

    return render_template('home.html', vulnerabilities=vulnerabilities)

@app.route('/home', methods=['GET', 'POST'])
def home():
   return render_template('home.html')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            msg = "Username already exists!"
        else:
            users[username] = generate_password_hash(password)
            msg = "Registered successfully. Please login."
            return redirect(url_for('login'))
    return render_template('register.html', msg=msg)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            msg = "Invalid credentials."
    return render_template('login.html', msg=msg)

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/result')
def result():
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        # Load the result data
        df_result = pd.read_excel("result_data.xlsx")

        # Filter data for the logged-in user
        user_data = df_result[df_result["username"] == session["username"]]

        # If the user's data is not empty, fetch the last entry
        if not user_data.empty:
            last_entry = user_data.iloc[-1].to_dict()
        else:
            last_entry = None

        return render_template('result.html', entry=last_entry)

    except FileNotFoundError:
        return render_template('result.html', entry=None)

    except Exception as e:
        return f"An error occurred: {str(e)}"

# All results
"""
@app.route('/result_store')
def result_store():
    if 'username' not in session:
        return redirect(url_for('login'))
    df_result = pd.read_excel("result_data.xlsx")
    user_data = df_result[df_result["username"] == session["username"]]
    return render_template('result_store.html', table=user_data.to_html(classes="table table-striped", index=False))
"""
@app.route('/result_store')
def result_store():
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        # Load the Excel file
        df_result = pd.read_excel("result_data.xlsx")

        # Filter the DataFrame for the logged-in user
        user_data = df_result[df_result["username"] == session["username"]]

        # Convert to HTML table with Bootstrap classes
        table_html = user_data.to_html(classes="table table-striped table-bordered text-white", index=False)

        return render_template('result_store.html', table=table_html)

    except Exception as e:
        return f"An error occurred while loading your results: {e}"

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    vulnerabilities = []
    if request.method == 'POST':
        website = request.form['website']
        if not website.startswith("http"):
            website = "http://" + website

        if is_valid_url(website):
            vulnerabilities = scan_website(website)

            result_df = pd.read_excel("result_data.xlsx")

            for v in vulnerabilities:
                result_df.loc[len(result_df)] = [
                    session.get('username', 'Guest'),  # Save username if available, else Guest
                    website,
                    v[0],  # Vulnerability Type
                    v[1]   # Description
                ]

            result_df.to_excel("result_data.xlsx", index=False)
        else:
            vulnerabilities = [("Error", "Invalid URL provided", "", "")]

    return render_template('predict.html', vulnerabilities=vulnerabilities)



@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Read Excel
    df = pd.read_excel("result_data.xlsx")

    # Filter by logged-in user
    user_data = df[df['username'] == session['username']]

    # Chart 1: Vulnerability type distribution
    vuln_counts = user_data['vulnerability'].value_counts().to_dict()

    # Chart 2: Vulnerabilities per website
    site_counts = user_data['website'].value_counts().to_dict()

    return render_template("dashboard.html",
                           vuln_data=json.dumps(vuln_counts),
                           site_data=json.dumps(site_counts))

# About + Feedback
@app.route('/about', methods=['GET', 'POST'])
def about():
    msg = ""
    if request.method == 'POST':
        feedback = request.form['feedback']
        with open("feedback.txt", "a") as f:
            f.write(f"{session.get('username', 'Guest')}: {feedback}\n")
        msg = "Thank you for your feedback!"
    return render_template('about.html', msg=msg)

if __name__ == '__main__':
    app.run(debug=True)
