import sys
import os
import json
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner.port_scanner import thread_scan
from threat_intel.checker import (
    full_threat_check,
    load_malicious_ports,
    fetch_firehol_ips,
    check_threats,
    check_ip_threat
)
from api.abuseipdb import check_abuseipdb


def save_report(target_ip, ports_data, abuseipdb_data, firehol_flagged, flagged_ports):
    report = {
        "target": target_ip,
        "open_ports": ports_data,
        "flagged_ports": flagged_ports,
        "firehol_blacklisted": firehol_flagged,
        "abuseipdb_info": abuseipdb_data
    }
    os.makedirs("output", exist_ok=True)
    print("[+] Output directory confirmed.")

    output_path = os.path.join(os.getcwd(), "output", "scan_report.json")
    print(f"[+] Saving report to {output_path}")

    try:
        with open(output_path, "w") as f:
            json.dump(report, f, indent=4)
        print(f"[+] Scan report saved to {output_path}")
    except Exception as e:
        print(f"[-] Failed to save report: {e}")
        raise  # Re-raise the exception to ensure the error is visible


def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]

    print(f"[+] Scanning target: {target_ip}")

    # Step 1: Multithreaded port scan with banners
    open_ports = thread_scan(target_ip, range(1, 1025))  # Adjust the port range as needed
    open_ports_list = [{"port": port["port"], "banner": port.get("banner", "No Banner")} for port in open_ports]  # Extract port and banner info
    print(f"\n[+] Open Ports: {[port['port'] for port in open_ports_list]}")

    # Step 2: Load known malicious ports list and check
    malicious_ports = load_malicious_ports()
    flagged_ports = check_threats([p["port"] for p in open_ports_list], malicious_ports)

    if flagged_ports:
        print(f"[!] Suspicious ports detected: {flagged_ports}")
    else:
        print("[-] No suspicious ports found.")

    # Step 3: Check IP against FireHOL threat feed
    threat_info = full_threat_check(target_ip, open_ports_list)
    
    firehol_flagged = threat_info.get("ip_threat", False)
    if firehol_flagged:
        print(f"[!] IP {target_ip} is flagged in FireHOL!")
    else:
        print(f"[-] IP {target_ip} is clean (not found in FireHOL).")

    if threat_info.get("suspicious_ports"):
        print(f"[!] Suspicious Ports Detected: {threat_info['suspicious_ports']}")
    else:
        print("[-] No suspicious ports found.")
    
    # Step 4: Query AbuseIPDB threat intelligence
    abuseipdb_data = check_abuseipdb(target_ip)
    if abuseipdb_data:
        print(f"[!] AbuseIPDB Score: {abuseipdb_data['abuseConfidenceScore']}")
    else:
        print("[-] AbuseIPDB lookup failed or no data found.")

    # Step 5: Save everything to JSON report
    print("[+] Preparing to save the report.")
    save_report(target_ip, open_ports_list, abuseipdb_data, firehol_flagged, flagged_ports)


if __name__ == '__main__':
    main()
