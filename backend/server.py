from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
import sqlite3
import bcrypt
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import socket
import ipaddress

app = Flask(__name__)
CORS(app)

# JWT Configuration
app.config["JWT_SECRET_KEY"] = "super-secret-key-change-in-production"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
jwt = JWTManager(app)

VULNERABILITY_DB = {
    "smb-vuln-ms17-010": {
        "name": "EternalBlue (SMBv1)",
        "severity": 10,
        "remediation": "1. Disable SMBv1\n2. Apply MS17-010 patch",
        "attack_simulation": "Ransomware deployment via SMBv1",
        "category": "Windows"
    },
    "http-vuln-cve2021-42013": {
        "name": "Apache Path Traversal",
        "severity": 9,
        "remediation": "Upgrade Apache to 2.4.51+",
        "attack_simulation": "Sensitive file disclosure",
        "category": "Web"
    }
}

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL)''')
    conn.commit()
    conn.close()

init_db()

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"msg": "Missing email or password"}), 400

    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)",
                 (email, hash_password(password)))
        conn.commit()
        return jsonify({"msg": "User created"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"msg": "Email already exists"}), 400
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"msg": "Missing email or password"}), 400

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    conn.close()

    if user and verify_password(password, user[0]):
        access_token = create_access_token(identity=email)
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Invalid credentials"}), 401

def resolve_target(target):
    try:
        if '-' in target:
            base, end = target.split('-')
            base_parts = base.split('.')
            return [str(ip) for ip in ipaddress.IPv4Network(f"{base}/24")][:int(end)+1]
        elif not target.replace('.', '').isdigit():
            return [socket.gethostbyname(target)]
        return [target]
    except Exception as e:
        return []

def parse_nmap_xml(xml_data):
    root = ET.fromstring(xml_data)
    results = {'open_ports': [], 'vulnerabilities': []}
    
    for host in root.findall('host'):
        for port in host.findall('.//port'):
            port_id = port.get('portid')
            state = port.find('state').get('state')
            if state == 'open':
                results['open_ports'].append(int(port_id))
                for script in port.findall('.//script'):
                    script_id = script.get('id')
                    if 'VULNERABLE' in script.get('output', ''):
                        vuln = VULNERABILITY_DB.get(script_id, {})
                        results['vulnerabilities'].append({
                            **vuln,
                            "port": port_id
                        })
    return results

@app.route('/scan', methods=['POST'])
@jwt_required()
def scan():
    data = request.json
    target = data.get('target', '127.0.0.1')
    duration = data.get('duration', 5)
    
    targets = resolve_target(target)
    all_results = []
    
    for ip in targets:
        try:
            command = [
                'nmap', '-T4', '-Pn',
                '-p', '80,443,445,22',
                '--script', 'smb-vuln-*,http-vuln-*,ssh-vuln-*',
                '-oX', '-',
                ip
            ]
            result = subprocess.run(command, capture_output=True, text=True, timeout=duration*60)
            
            if result.returncode != 0:
                continue
                
            parsed = parse_nmap_xml(result.stdout)
            parsed['ip'] = ip
            parsed['timestamp'] = datetime.now().isoformat()
            all_results.append(parsed)
            
        except Exception as e:
            continue

    return jsonify({"target": target, "results": all_results})

@app.route('/report', methods=['POST'])
@jwt_required()
def generate_report():
    data = request.json
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    
    p.setFont("Helvetica-Bold", 16)
    p.drawString(100, 750, "LogicBreach Red Team Report")
    p.drawString(100, 730, f"Target: {data['target']}")
    
    y = 700
    p.setFont("Helvetica", 12)
    for result in data['results']:
        for vuln in result['vulnerabilities']:
            p.drawString(100, y, f"IP: {result['ip']} | {vuln['name']}")
            p.drawString(100, y-20, f"Severity: {vuln['severity']}/10")
            y -= 40
    
    p.save()
    buffer.seek(0)
    return send_file(buffer, mimetype='application/pdf')

if __name__ == '__main__':
    app.run(port=3001)