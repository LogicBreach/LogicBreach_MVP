from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import xml.etree.ElementTree as ET

app = Flask(__name__)
CORS(app)

VULNERABILITY_DB = {
    "smb-vuln-ms17-010": {
        "name": "EternalBlue (SMBv1)",
        "severity": "Critical",
        "remediation": "1. Disable SMBv1. 2. Apply Windows MS17-010 patch.",
        "attack_simulation": "Attackers can deploy ransomware like WannaCry.",
        "cve": "CVE-2017-0144"
    }
}

def parse_nmap_xml(xml_data):
    root = ET.fromstring(xml_data)
    results = {"open_ports": [], "vulnerabilities": []}
    
    for host in root.findall('host'):
        for port in host.findall('.//port'):
            port_id = port.get('portid')
            state = port.find('state').get('state')
            if state == 'open':
                results["open_ports"].append(int(port_id))
                for script in port.findall('.//script'):
                    script_id = script.get('id')
                    output = script.get('output', '')
                    if 'VULNERABLE' in output:
                        vuln = VULNERABILITY_DB.get(script_id, {})
                        results["vulnerabilities"].append({
                            "name": vuln.get("name", "Unknown"),
                            "severity": vuln.get("severity", "Medium"),
                            "remediation": vuln.get("remediation", "Investigate manually."),
                            "cve": vuln.get("cve", "N/A")
                        })
    return results

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    ip = data.get('ip', '127.0.0.1')
    
    try:
        # Run Nmap scan for SMB vulnerability
        command = [
            'nmap',
            '-p', '445',
            '--script', 'smb-vuln-ms17-010',
            '-oX', '-',  # Output XML to stdout
            ip
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            return jsonify({"error": f"Nmap failed: {result.stderr}"}), 500
        
        parsed_data = parse_nmap_xml(result.stdout)
        parsed_data["ip"] = ip
        parsed_data["attack_report"] = ["Simulated ransomware deployment via SMBv1"] if parsed_data["vulnerabilities"] else []
        parsed_data["ai_analysis"] = "🔴 Critical risk!" if parsed_data["vulnerabilities"] else "🟢 No issues found."
        
        return jsonify(parsed_data)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=3001)