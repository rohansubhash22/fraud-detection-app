import re
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import uuid # For generating unique IDs for reports

app = Flask(__name__)
CORS(app)

# --- Your existing URL fraud detection logic ---
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

# --- Existing Transaction Fraud Detection Logic ---
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

# --- NEW: Identity Theft Detection (Placeholder) ---
def analyze_identity_theft_indicators(data_points):
    """
    Simulates identity theft detection based on provided indicators.
    In a real system, this would involve more complex checks,
    e.g., against data breaches, credit reports, etc.
    `data_points` could be a dictionary of indicators like
    {"unusual_credit_inquiry": true, "unrecognized_account": false, ...}
    """
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

    if not is_compromised:
        reasons.append("No common identity theft indicators found based on provided data.")

    return {
        "is_compromised": is_compromised,
        "reasons": reasons,
        "indicators_provided": data_points
    }

# --- NEW: Report Fraud (Placeholder for Storage) ---
# In a real application, you would save this to a database (SQL, NoSQL),
# send it to a queue, or an internal reporting system.
# For this example, we'll just store it in memory.
fraud_reports = []

def submit_fraud_report(report_data):
    """
    Submits a fraud report. Generates a unique ID and stores it.
    """
    report_id = str(uuid.uuid4()) # Generate a unique ID for the report
    report_data["report_id"] = report_id
    report_data["timestamp"] = app.current_time.strftime("%Y-%m-%d %H:%M:%S") # Add a timestamp
    fraud_reports.append(report_data) # Store in memory
    print(f"New Fraud Report Submitted: {report_id} - {report_data}") # For demonstration
    return {"status": "success", "report_id": report_id, "message": "Fraud report received."}

# --- Flask Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze-url', methods=['POST'])
def analyze_url_endpoint():
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

# --- NEW: Identity Theft Endpoint ---
@app.route('/analyze-identity-theft', methods=['POST'])
def analyze_identity_theft_endpoint():
    data = request.get_json()
    # Expect data to be a dictionary of boolean indicators
    # e.g., {"unusual_credit_inquiry": true, "unrecognized_account": false}
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid input format. Expected a JSON object with boolean indicators."}), 400

    analysis_results = analyze_identity_theft_indicators(data)
    return jsonify(analysis_results)

# --- NEW: Report Fraud Endpoint ---
@app.route('/submit-fraud-report', methods=['POST'])
def submit_fraud_report_endpoint():
    report_data = request.get_json()
    if not isinstance(report_data, dict):
        return jsonify({"error": "Invalid input format. Expected a JSON object with report details."}), 400

    # Basic validation for report fields
    if not report_data.get('fraud_type'):
        return jsonify({"error": "Fraud type is required."}), 400
    if not report_data.get('description'):
        return jsonify({"error": "Description is required."}), 400
    if not report_data.get('contact_email') and not report_data.get('contact_phone'):
        return jsonify({"error": "At least one contact method (email or phone) is required."}), 400

    response = submit_fraud_report(report_data)
    return jsonify(response)

if __name__ == '__main__':
    import datetime
    app.current_time = datetime.datetime.now() # Store current time for timestamping reports
    app.run(debug=True, host='0.0.0.0', port=5000)