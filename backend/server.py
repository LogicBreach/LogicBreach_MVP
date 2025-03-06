from flask import Flask, request, jsonify
from flask_cors import CORS
import nmap

app = Flask(__name__)
CORS(app)
scanner = nmap.PortScanner()

@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
    ip = data.get('ip', '127.0.0.1')  # Default to localhost

    # Scan port 445 for testing (simulate a vulnerability)
    scanner.scan(ip, arguments='-p 445')

    results = {
        'ip': ip,
        'open_ports': scanner[ip].all_tcp() if ip in scanner.all_hosts() else [],
        'vulnerabilities': []
    }

    # ====== MOCK VULNERABILITY (FOR TESTING) ====== #
    results['vulnerabilities'].append("🚨 Critical risk: Mock vulnerability on port 445!")
    # ============================================== #

    return jsonify(results)

if __name__ == '__main__':
    app.run(port=3001)  # Runs on port 3001 to avoid conflicts