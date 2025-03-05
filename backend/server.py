from flask import Flask, request, jsonify
from flask_cors import CORS  # Required for frontend-backend communication
import nmap

app = Flask(__name__)
CORS(app)  # Enable CORS to avoid frontend connection issues
scanner = nmap.PortScanner()

@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
    ip = data.get('ip', '127.0.0.1')  # Default to localhost

    # Scan for open ports and service versions (-sV flag)
    scanner.scan(ip, arguments='-p 1-1000 -sV')

    results = {
        'ip': ip,
        'open_ports': scanner[ip].all_tcp() if ip in scanner.all_hosts() else [],
        'vulnerabilities': []
    }

    # Check for vulnerabilities in open ports
    for port in results['open_ports']:
        service = scanner[ip]['tcp'][port]['name']
        version = scanner[ip]['tcp'][port]['version']
        
        # Detect SMB vulnerability (example)
        if 'smb' in service.lower():
            results['vulnerabilities'].append(
                f"SMB vulnerability (CVE-2017-0144) detected on port {port}!"
            )

    return jsonify(results)

if __name__ == '__main__':
    app.run(port=3000)