import re
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import datetime

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# For Flask sessions: a strong secret key is crucial in production
# GENERATE A REAL SECRET KEY FOR PRODUCTION:
# import secrets
# print(secrets.token_hex(16))
app.secret_key = 'your_super_secret_key_here_replace_this_in_production'
# You should generate a complex key: e.g., import os; os.urandom(24)

# --- In-memory user database (REPLACE WITH A REAL DATABASE IN PRODUCTION) ---
# Stores user_email: { 'password_hash': '...', 'first_name': '...', ... }
users_db = {} # Example: {'test@example.com': {'password_hash': 'pbkdf2:sha256:...', 'first_name': 'Test', 'last_name': 'User', 'company': 'ABC Corp'}}

# --- Existing Fraud Detection Logic (unchanged from previous iterations) ---
MALICIOUS_DOMAINS = [
    "example-phishing.com", "badsite.net", "scamdomain.info", "malware-distro.org"
]
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "account", "verify", "update", "security",
    "webscr", "confirm", "paypal", "bank", "amazon", "appleid",
    "microsoft", "support", "secure"
]

def analyze_url_for_fraud(url):
    results = {
        "is_fraudulent": False, "reasons": [], "parsed_url": None,
        "domain": None, "path": None, "query": None
    }
    try:
        parsed_url = urlparse(url)
        results["parsed_url"] = {
            "scheme": parsed_url.scheme, "netloc": parsed_url.netloc,
            "path": parsed_url.path, "params": parsed_url.params,
            "query": parsed_url.query, "fragment": parsed_url.fragment
        }
        results["domain"] = parsed_url.netloc
        results["path"] = parsed_url.path
        results["query"] = parsed_url.query

        if parsed_url.netloc in MALICIOUS_DOMAINS:
            results["is_fraudulent"] = True
            results["reasons"].append(f"Domain '{parsed_url.netloc}' found in blacklist.")
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.netloc):
            results["is_fraudulent"] = True
            results["reasons"].append("IP address used in hostname.")
        if len(url) > 100:
            results["is_fraudulent"] = True
            results["reasons"].append(f"Excessive URL length ({len(url)} characters).")
        url_lower = url.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                results["is_fraudulent"] = True
                results["reasons"].append(f"Suspicious keyword '{keyword}' found in URL.")
                break
        if parsed_url.netloc.count('.') > 3:
            results["is_fraudulent"] = True
            results["reasons"].append("Unusual number of dots in domain (potential subdomain abuse).")
        if "@" in parsed_url.netloc:
            results["is_fraudulent"] = True
            results["reasons"].append("'@' symbol found in domain/subdomain (potential credential embedding).")
    except Exception as e:
        results["reasons"].append(f"Error parsing URL: {e}")
        results["is_fraudulent"] = True
    return results

# --- Existing Transaction Fraud Detection Logic (unchanged) ---
SUSPICIOUS_LOCATIONS = ["Nigeria", "North Korea", "Iran", "Venezuela"]
HIGH_AMOUNT_THRESHOLD = 1000.0

def analyze_transaction_for_fraud(amount, location, card_type):
    results = {
        "is_fraudulent": False, "reasons": [],
        "transaction_details": {"amount": amount, "location": location, "card_type": card_type}
    }
    if amount > HIGH_AMOUNT_THRESHOLD:
        results["is_fraudulent"] = True
        results["reasons"].append(f"Transaction amount (${amount:.2f}) exceeds high amount threshold (${HIGH_AMOUNT_THRESHOLD:.2f}).")
    if location and location.lower() in [loc.lower() for loc in SUSPICIOUS_LOCATIONS]:
        results["is_fraudulent"] = True
        results["reasons"].append(f"Transaction from a suspicious location: {location}.")
    if card_type and card_type.lower() == "prepaid":
        results["is_fraudulent"] = True
        results["reasons"].append("Transaction made with a prepaid card (often associated with higher fraud risk).")

    if results["is_fraudulent"] and not results["reasons"]:
        results["reasons"].append("Transaction flagged as fraudulent by general rules (no specific reason listed in simplified model).")
    elif not results["is_fraudulent"] and not results["reasons"]:
         results["reasons"].append("No specific red flags found by current rules.")
    return results

# --- Existing Identity Theft Detection (Placeholder) (unchanged) ---
def analyze_identity_theft_indicators(data_points):
    is_compromised = False
    reasons = []

    if data_points.get("unusual_credit_inquiry"):
        is_compromised = True
        reasons.append("Unusual credit inquiry detected.")
    if data_points.get("unrecognized_account"):
        is_compromised = True
        reasons.append("Unrecognized new account opened in your name.")
    if data_points.get("suspicious_mail"):
        is_compromised = True
        reasons.append("Suspicious mail (e.g., debt collection for unknown accounts).")
    if data_points.get("data_breach_alert"):
        is_compromised = True
        reasons.append("Your information was part of a known data breach.")
    if data_points.get("unauthorized_access"):
        is_compromised = True
        reasons.append("Unauthorized access attempts to your online accounts.")
    if data_points.get("id_stolen"):
        is_compromised = True
        reasons.append("Physical ID (e.g., driver's license, passport) reported stolen.")

    if not is_compromised:
        reasons.append("No common identity theft indicators found based on provided data.")

    return {
        "is_compromised": is_compromised,
        "reasons": reasons,
        "indicators_provided": data_points
    }

# --- Existing Report Fraud (Placeholder for Storage) (unchanged) ---
fraud_reports = []

def submit_fraud_report(report_data):
    report_id = str(uuid.uuid4())
    report_data["report_id"] = report_id
    report_data["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fraud_reports.append(report_data)
    print(f"New Fraud Report Submitted: {report_id} - {report_data}")
    return {"status": "success", "report_id": report_id, "message": "Fraud report received."}

# --- NEW: Flask Routes for Authentication ---

# Redirects root URL to login page
@app.route('/')
def root_redirect():
    return redirect(url_for('login_page'))

# Serves the login page
@app.route('/login')
def login_page():
    return render_template('login.html')

# Serves the signup page
@app.route('/signup')
def signup_page():
    return render_template('signup1.html')

# Handles user registration
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    first_name = data.get('firstName')
    last_name = data.get('lastName')
    company = data.get('company')
    email = data.get('email')
    password = data.get('password')

    if not all([first_name, last_name, company, email, password]):
        return jsonify({"status": "error", "message": "All fields are required."}), 400

    if email in users_db:
        return jsonify({"status": "error", "message": "Email already registered."}), 409 # Conflict

    # Hash the password before storing
    hashed_password = generate_password_hash(password)

    users_db[email] = {
        'password_hash': hashed_password,
        'first_name': first_name,
        'last_name': last_name,
        'company': company
    }
    print(f"New user registered: {email}") # For demonstration
    return jsonify({"status": "success", "message": "Registration successful! You can now log in."}), 201 # Created

# Handles user login authentication
@app.route('/authenticate', methods=['POST'])
def authenticate_user():
    data = request.get_json()
    email = data.get('username') # Using 'username' from login form, which is email here
    password = data.get('password')

    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password are required."}), 400

    user_data = users_db.get(email)

    if user_data and check_password_hash(user_data['password_hash'], password):
        # Set user in session
        session['logged_in'] = True
        session['user_email'] = email
        session['user_first_name'] = user_data['first_name'] # Store for display if needed
        return jsonify({"status": "success", "message": "Login successful!"})
    else:
        return jsonify({"status": "error", "message": "Invalid email or password."}), 401

# Handles user logout
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('user_email', None)
    session.pop('user_first_name', None)
    return redirect(url_for('login_page'))

# --- Protected Main Application Route ---
@app.route('/main')
def main_app():
    if not session.get('logged_in'):
        # If not logged in, redirect to login page
        flash('Please log in to access this page.', 'info') # Optional: use flash messages for user feedback
        return redirect(url_for('login_page'))
    # If logged in, render the main application page
    return render_template('index.html', user_first_name=session.get('user_first_name'))

# --- Existing API Endpoints (accessible after main_app is loaded) ---
@app.route('/analyze-url', methods=['POST'])
def analyze_url_endpoint():
    # In a real app, you might add session check here too for direct API calls
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    analysis_results = analyze_url_for_fraud(url)
    return jsonify(analysis_results)

@app.route('/analyze-transaction', methods=['POST'])
def analyze_transaction_endpoint():
    data = request.get_json()
    amount = data.get('amount')
    location = data.get('location')
    card_type = data.get('card_type')

    if not isinstance(amount, (int, float)):
        return jsonify({"error": "Amount must be a number"}), 400
    if not isinstance(location, str):
        return jsonify({"error": "Location must be a string"}), 400
    if not isinstance(card_type, str):
        return jsonify({"error": "Card type must be a string"}), 400

    analysis_results = analyze_transaction_for_fraud(amount, location, card_type)
    return jsonify(analysis_results)

@app.route('/analyze-identity-theft', methods=['POST'])
def analyze_identity_theft_endpoint():
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid input format. Expected a JSON object with boolean indicators."}), 400

    analysis_results = analyze_identity_theft_indicators(data)
    return jsonify(analysis_results)

@app.route('/submit-fraud-report', methods=['POST'])
def submit_fraud_report_endpoint():
    report_data = request.get_json()
    if not isinstance(report_data, dict):
        return jsonify({"error": "Invalid input format. Expected a JSON object with report details."}), 400

    if not report_data.get('fraud_type'):
        return jsonify({"error": "Fraud type is required."}), 400
    if not report_data.get('description'):
        return jsonify({"error": "Description is required."}), 400
    if not report_data.get('contact_email') and not report_data.get('contact_phone'):
        return jsonify({"error": "At least one contact method (email or phone) is required."}), 400

    response = submit_fraud_report(report_data)
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
