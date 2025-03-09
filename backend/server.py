from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
import socket
import ipaddress
import json
import time
import threading

app = Flask(__name__)
CORS(app)

# Enhanced Vulnerability Database
VULNERABILITY_DB = {
    "smb-vuln-ms17-010": {
        "name": "EternalBlue (SMBv1)",
        "severity": 10,
        "remediation": "1. Disable SMBv1\n2. Apply MS17-010 patch",
        "attack_simulation": "Ransomware deployment via SMBv1",
        "category": "Windows",
        "cve": "CVE-2017-0144",
        "mitre_tactics": ["TA0001", "TA0002"]
    },
    "http-vuln-cve2021-42013": {
        "name": "Apache Path Traversal",
        "severity": 9,
        "remediation": "Upgrade Apache to 2.4.51+",
        "attack_simulation": "Sensitive file disclosure",
        "category": "Web",
        "cve": "CVE-2021-42013",
        "mitre_tactics": ["TA0003", "TA0007"]
    }
}

# Compliance Checklists
COMPLIANCE_FRAMEWORKS = {
    "PCI_DSS": {
        "requirements": [
            "Install and maintain firewall",
            "Protect stored cardholder data",
            "Encrypt transmission of cardholder data",
            "Use antivirus software",
            "Restrict physical access to data"
        ],
        "passing_score": 4
    },
    "HIPAA": {
        "requirements": [
            "Risk analysis implementation",
            "Workstation security",
            "Access control implementation",
            "Audit controls",
            "Transmission security"
        ],
        "passing_score": 4
    }
}

# Scan Status Tracking
active_scans = {}

def generate_attack_graph(results):
    nodes = []
    links = []
    
    for idx, host in enumerate(results['results']):
        nodes.append({
            "id": host['ip'],
            "label": f"Host {host['ip']}",
            "group": "host",
            "value": len(host['vulnerabilities'])
        })
        
        for vuln in host['vulnerabilities']:
            vuln_id = f"{host['ip']}_{vuln['name']}"
            nodes.append({
                "id": vuln_id,
                "label": vuln['name'],
                "group": "vulnerability",
                "severity": vuln['severity']
            })
            links.append({
                "from": host['ip'],
                "to": vuln_id,
                "label": "CONTAINS"
            })
            
            if "exploited" in vuln:
                nodes.append({
                    "id": f"{vuln_id}_exploit",
                    "label": "Exploited",
                    "group": "exploit"
                })
                links.append({
                    "from": vuln_id,
                    "to": f"{vuln_id}_exploit",
                    "label": "EXPLOITED"
                })
    
    return {"nodes": nodes, "links": links}

def scan_worker(target, scan_id):
    try:
        targets = resolve_target(target)
        results = []
        
        for ip in targets:
            command = [
                'nmap', '-T4', '-Pn',
                '-p', '80,443,445,22,3389',
                '--script', 'smb-vuln-*,http-vuln-*,ssh-vuln-*',
                '-oX', '-',
                ip
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                parsed = parse_nmap_xml(result.stdout)
                parsed['ip'] = ip
                parsed['timestamp'] = datetime.now().isoformat()
                
                # Simulate exploit
                if "smb-vuln-ms17-010" in [v['id'] for v in parsed['vulnerabilities']]:
                    parsed['exploit'] = {
                        "status": "success",
                        "payload": "EternalBlue",
                        "impact": "SYSTEM_ACCESS"
                    }
                
                results.append(parsed)
        
        compliance = {}
        for framework in COMPLIANCE_FRAMEWORKS:
            passed = sum(1 for req in COMPLIANCE_FRAMEWORKS[framework]['requirements'] if check_compliance(req))
            compliance[framework] = {
                "passed": passed,
                "total": len(COMPLIANCE_FRAMEWORKS[framework]['requirements']),
                "status": "Pass" if passed >= COMPLIANCE_FRAMEWORKS[framework]['passing_score'] else "Fail"
            }
        
        active_scans[scan_id] = {
            "status": "completed",
            "results": results,
            "attack_graph": generate_attack_graph({"results": results}),
            "compliance": compliance,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        active_scans[scan_id] = {
            "status": "failed",
            "error": str(e)
        }

@app.route('/scan', methods=['POST'])
def start_scan():
    data = request.json
    scan_id = f"scan_{int(time.time())}"
    
    active_scans[scan_id] = {"status": "running", "progress": 0}
    thread = threading.Thread(target=scan_worker, args=(data.get('target', ''), scan_id))
    thread.start()
    
    return jsonify({"scan_id": scan_id})

@app.route('/scan-status/<scan_id>')
def get_scan_status(scan_id):
    return jsonify(active_scans.get(scan_id, {"status": "unknown"}))

@app.route('/report', methods=['POST'])
def generate_report():
    data = request.json
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Header
    story.append(Paragraph("LogicBreach Security Report", styles['Title']))
    story.append(Spacer(1, 12))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", styles['Heading2']))
    story.append(Paragraph(f"""
        <b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d')}<br/>
        <b>Target:</b> {data['target']}<br/>
        <b>Total Vulnerabilities:</b> {sum(len(h['vulnerabilities']) for h in data['results'])}<br/>
        <b>Critical Findings:</b> {sum(1 for h in data['results'] for v in h['vulnerabilities'] if v['severity'] >= 9)}
    """, styles['Normal']))
    
    # Compliance Status
    story.append(Paragraph("Compliance Status", styles['Heading2']))
    for framework in data.get('compliance', {}):
        status = data['compliance'][framework]
        story.append(Paragraph(f"""
            <b>{framework}:</b> {status['passed']}/{status['total']} ({status['status']})
        """, styles['Normal']))
    
    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, mimetype='application/pdf')

if __name__ == '__main__':
    app.run(port=3001, threaded=True)