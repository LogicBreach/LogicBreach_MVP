import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
import ipaddress
import socket
import re

app = Flask(__name__)
CORS(app)

VULNERABILITY_DB = {
    "smb-vuln-ms17-010": {
        "name": "EternalBlue (SMBv1)",
        "severity": 10,
        "remediation": "1. Disable SMBv1\n2. Apply MS17-010 patch",
        "category": "Windows"
    },
    "http-vuln-cve2021-42013": {
        "name": "Apache Path Traversal",
        "severity": 9,
        "remediation": "Upgrade Apache to 2.4.51+",
        "category": "Web"
    }
}

def resolve_target(target):
    try:
        if '-' in target:
            base, end = target.split('-')
            base_ip = ipaddress.IPv4Address(base)
            return [str(base_ip + i) for i in range(int(end) + 1)]
        elif '/' in target:
            return [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
        elif not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            return [socket.gethostbyname(target)]
        else:
            return [str(ipaddress.IPv4Address(target))]
    except Exception as e:
        print(f"Resolution Error: {str(e)}")
        return []

def parse_nmap_xml(xml_data):
    try:
        root = ET.fromstring(xml_data)
        results = {'open_ports': [], 'vulnerabilities': []}
        
        for host in root.findall('host'):
            for port in host.findall('.//port'):
                port_id = port.get('portid')
                state = port.find('state').get('state') if port.find('state') else 'closed'
                
                if state == 'open':
                    results['open_ports'].append(port_id)
                    for script in port.findall('.//script'):
                        script_id = script.get('id', '')
                        if script_id in VULNERABILITY_DB:
                            results['vulnerabilities'].append({
                                **VULNERABILITY_DB[script_id],
                                "port": port_id
                            })
        return results
    except Exception as e:
        print(f"Parse Error: {str(e)}")
        return {'open_ports': [], 'vulnerabilities': []}

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        target = data.get('target', '')
        
        # Validate input
        if not re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(-\d+)?$|^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/\d{1,2}$|^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return jsonify({"error": "Invalid format. Use: 192.168.1.1-10, 192.168.1.0/24, or domain.com"}), 400

        targets = resolve_target(target)
        if not targets:
            return jsonify({"error": "No valid targets found"}), 400

        results = []
        for ip in targets:
            try:
                command = [
                    'nmap', '-T4', '-Pn',
                    '-p', '80,443,445,22,3389',
                    '--script', 'smb-vuln-*,http-vuln-*',
                    '-oX', '-',
                    ip
                ]
                result = subprocess.run(command, capture_output=True, text=True, timeout=300)
                
                if result.returncode == 0:
                    parsed = parse_nmap_xml(result.stdout)
                    parsed['ip'] = ip
                    parsed['timestamp'] = datetime.now().isoformat()
                    results.append(parsed)
                    
            except Exception as e:
                print(f"Scan Error for {ip}: {str(e)}")

        # Safe attack path generation
        attack_paths = []
        if results and len(results) > 0:
            for result in results:
                if result.get('vulnerabilities') and len(result['vulnerabilities']) > 0:
                    attack_paths.append({
                        "stage": "initial_access",
                        "details": result['vulnerabilities'][0]
                    })
                    break

        return jsonify({
            "target": target,
            "results": results,
            "attack_paths": attack_paths
        })

    except Exception as e:
        return jsonify({"error": f"Server Error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3001)