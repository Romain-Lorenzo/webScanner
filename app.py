from flask import Flask, render_template, request
from requests import get

app = Flask(__name__)

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

if __name__ == '__main__':
    app.run(debug=True)