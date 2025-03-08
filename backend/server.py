from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

app = Flask(__name__)
CORS(app)

# Mock Vulnerability Database
VULNERABILITY_DB = {
    "smb-vuln-ms17-010": {
        "name": "EternalBlue (SMBv1)",
        "severity": 10,
        "remediation": "Disable SMBv1 and apply MS17-010 patch.",
        "attack_simulation": "Ransomware deployment via SMBv1."
    }
}

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    ip = data.get('ip', '127.0.0.1')
    
    # Mock response (no real scanning)
    return jsonify({
        "ip": ip,
        "open_ports": [445],
        "vulnerabilities": [VULNERABILITY_DB["smb-vuln-ms17-010"]],
        "ai_analysis": "🔴 Critical risk detected!",
        "timestamp": "2024-03-08T12:00:00"  # Fake timestamp for testing
    })

@app.route('/report/<ip>', methods=['GET'])
def generate_report(ip):
    try:
        # Create a fake PDF for testing
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        
        p.setFont("Helvetica-Bold", 16)
        p.drawString(100, 750, "LogicBreach Security Report")
        p.drawString(100, 730, f"Target: {ip}")
        
        p.setFont("Helvetica", 12)
        p.drawString(100, 700, "Test Vulnerability: EternalBlue (SMBv1)")
        p.drawString(100, 680, "Severity: Critical")
        
        p.save()
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"LogicBreach_Report_{ip}.pdf"
        )
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=3001, debug=True)  # Debug mode for troubleshooting