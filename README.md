# ThreatMapX — Scan, Flag, and Threat-Tag

A Python scanner that identifies open ports and correlates them with known malicious services.

<div align="center">
<img width="600" alt="Screenshot 2025-04-28 at 5 02 15 PM" src="https://github.com/user-attachments/assets/8d9950cb-dfa3-4a71-ac34-8a01f2dee14a" />
<img width="600" alt="Screenshot 2025-04-28 at 5 03 24 PM" src="https://github.com/user-attachments/assets/e5ee67df-1280-42e7-942e-f7411b1a0517" />
</div>

# Features

- **🔎 Fast Port Scanning**
  - Multi-threaded scanning of **common ports** (e.g., 21, 22, 23, 80, 443, etc.)
  - Banner grabbing: tries to capture service information from open ports
  - Handles timeouts and socket errors gracefully

- **📜 Banner Analysis**
  - Displays any retrieved service banners (like SSH versions, HTTP server headers, FTP servers, etc.)
  - Reports when no banner is found or connection errors occur

- **🚨 Threat Detection via Port Matching**
  - Loads a **list of known malicious ports**
  - Checks if any open ports match **threatened/malicious ports** list
  - Alerts the user if dangerous ports are open

- **🛡️ IP Reputation Check**
  - Integrates with **AbuseIPDB API**
  - Checks the **abuse confidence score** and reports details like:
    - Country
    - Domain name (if available)
    - Whether IP is public (185.220.101.1)
    - Total number of reports
  - Helps judge if the scanned IP is suspicious

- **📂 Report Generation**
  - Saves scan results (open ports, banners, abuse check results) into a **JSON file**
  - Organized output for later analysis

- **🌐 External Blacklist Check**
  - Fetches FireHOL IP blacklist
  - Checks if target IP is blacklisted in threat databases
  - Used as a static additional check — "is this IP in a known bad list?"

- **🌟 Web Interface**
  - `app.py` builds a **web-based GUI** to scan IPs and view reports visually

---


# Installation

```
# Clone Repository
git clone https://github.com/shikha1149myprojects/PortScanner-With-Threat-Intelligence.git

# Move into directory
cd webapp

# Set Up virtual environment
python3 -m venv venv

# Activate venv For Linux/Max
source venv/bin/activate

# Activate venv For Windows
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run app
python3 app.py

```
