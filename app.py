from flask import Flask, render_template, request, jsonify
from requests import get
import requests

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
    
@app.route('/api/server-info', methods=['POST'])
def api_server_info():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request data"}), 400

    url = data["url"]

    try:
        # Step 1: Retrieve the IP address using Web-Check's DNS API
        dns_response = requests.get(f"http://webcheck:3000/api/dns?url={url}", timeout=10)
        dns_response.raise_for_status()
        dns_data = dns_response.json()

        # Extract IP address from the 'A' object if it exists
        ip_address = None
        if "A" in dns_data and isinstance(dns_data["A"], dict) and "address" in dns_data["A"]:
            ip_address = dns_data["A"]["address"]
        elif "address" in dns_data:  # Fallback in case structure changes
            ip_address = dns_data["address"]

        if not ip_address:
            return jsonify({"error": "Failed to retrieve IP address."}), 404

        # Step 2: Query ipapi.co with the IP address
        ipapi_response = requests.get(f"https://ipapi.co/{ip_address}/json/", timeout=10)
        ipapi_response.raise_for_status()
        server_info = ipapi_response.json()

        # Return the server info
        return jsonify(server_info)

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to fetch server info: {str(e)}"}), 500