import os
from flask import Flask, render_template, request, jsonify
from requests import get

app = Flask(__name__)

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    # Get URL
    data = request.get_json()
    url = data["url"]
    # Send to web-check
    response = get(f"http://webcheck:3000/api/firewall?url={url}")
    return response.json()

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/api/domains', methods=['POST'])
def api_domains():
    data = request.get_json()
    domain = data.get("domain")
    if not domain:
        return {"error": "Domain is required"}, 400
    domains = get_domains_from_crtsh(domain)
    return {"count": len(domains), "domains": domains}
def get_domains_from_crtsh(domain):
    try:
        response = get(f"https://crt.sh/?q={domain}&output=json&exclude=expired")
        if response.status_code == 200:
            data = response.json()
            # Extract unique domain names from the response
            domains = {entry["name_value"] for entry in data}
            return list(domains)
        else:
            return []
    except Exception as e:
        print(f"Error querying crt.sh: {e}")
        return []
    
@app.route('/api/whois', methods=['POST'])
def api_whois():
    data = request.get_json()
    domain = data.get("domain")

    if not domain:
        return {"error": "Domain is required"}, 400

    # Call the Web-Check API for WHOIS
    try:
        response = get(f"http://webcheck:3000/api/whois?url={domain}")
        if response.status_code != 200:
            return {"error": f"Web-Check API returned status {response.status_code}"}, response.status_code
        
        return response.json()
    except Exception as e:
        return {"error": f"Could not fetch WHOIS data: {str(e)}"}, 500

@app.route('/api/tls', methods=['POST'])
def api_tls():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request data"}), 400

    url = data["url"]
    try:
        # Make the request to the Web-Check TLS API
        response = get(f"http://webcheck:3000/api/tls?url={url}", timeout=10)
        response.raise_for_status()
        tls_data = response.json()  # Parse the response JSON

        # Find the object where analyzer is "mozillaGradingWorker"
        analysis = tls_data.get("analysis", [])
        grading_data = next(
            (item.get("result") for item in analysis if item.get("analyzer") == "mozillaGradingWorker"),
            None
        )

        # If grading data is found, extract grade and lettergrade
        if grading_data:
            grade = grading_data.get("grade")
            lettergrade = grading_data.get("lettergrade")
            return jsonify({"grade": grade, "lettergrade": lettergrade})

        # If no relevant data found
        return jsonify({"error": "Mozilla grading data not found"}), 404

    except Exception as e:
        return jsonify({"error": f"Failed to fetch TLS data: {str(e)}"}), 500