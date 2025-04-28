# AbuseIPDB threat check

import requests

ABUSEIPDB_API_KEY = "a7792ce10196d8ddc78f81c321538393cba3cf4cc64583391db4768a91b9d8a25e2e5bb18baaec93"  # Get from https://www.abuseipdb.com/

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        print("[DEBUG] Raw response:", response.text)  
        data = response.json()["data"]
        return {
            "abuseConfidenceScore": data["abuseConfidenceScore"],
            "countryCode": data["countryCode"],
            "domain": data["domain"],
            "isPublic": data["isPublic"],
            "totalReports": data["totalReports"]
        }
    except Exception as e:
        print(f"[Error] AbuseIPDB check failed: {e}")
        return None

#print(check_abuseipdb("185.220.101.1"))  # Known malicious Tor exit node
