from flask import Flask, render_template, request
from scanner.port_scanner import thread_scan, common_ports
from threat_intel.checker import load_malicious_ports, check_threats, fetch_firehol_ips, check_ip_threat
from api.abuseipdb import check_abuseipdb
import ipaddress
import os
import json

app = Flask(__name__)

# Load FireHOL IPs once when app starts (optional optimization)
firehol_ips = fetch_firehol_ips()

def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False

def save_report(target_ip, open_ports, flagged_ports, is_ip_blacklisted, abuse_info):
    report = {
        "target_ip": target_ip,
        "open_ports": open_ports,
        "flagged_ports": flagged_ports,
        "is_ip_blacklisted": is_ip_blacklisted,
        "abuse_info": abuse_info
    }
    
    # Create output directory if it doesn't exist
    os.makedirs("output", exist_ok=True)
    
    output_path = os.path.join(os.getcwd(), "output", f"scan_report_{target_ip}.json")
    try:
        with open(output_path, "w") as f:
            json.dump(report, f, indent=4)
        print(f"[+] Scan report saved to {output_path}")
    except Exception as e:
        print(f"[-] Failed to save report: {e}")

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        target_ip = request.form['target_ip']

        # Perform scans
        open_ports = thread_scan(target_ip, common_ports)
        malicious_ports = load_malicious_ports()
        flagged_ports = check_threats([p["port"] for p in open_ports], malicious_ports)

        # 🛡️ New: Only check blacklist if IP is public
        if is_public_ip(target_ip):
            is_ip_blacklisted = check_ip_threat(target_ip, firehol_ips)
        else:
            is_ip_blacklisted = False

        abuse_info = check_abuseipdb(target_ip)

        # Save the report
        save_report(target_ip, open_ports, flagged_ports, is_ip_blacklisted, abuse_info)

        return render_template('result.html',
                               target_ip=target_ip,
                               open_ports=open_ports,
                               flagged_ports=flagged_ports,
                               is_ip_blacklisted=is_ip_blacklisted,
                               abuse_info=abuse_info)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
