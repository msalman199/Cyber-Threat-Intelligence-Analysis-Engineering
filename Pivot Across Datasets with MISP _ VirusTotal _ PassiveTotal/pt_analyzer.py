#!/usr/bin/env python3
import requests
import json
import base64
from api_config import PT_API_KEY, PT_USERNAME, DEMO_MODE

class PTAnalyzer:
    def __init__(self):
        self.api_key = PT_API_KEY
        self.username = PT_USERNAME
        self.base_url = "https://api.passivetotal.org/v2/"
        
    def get_auth_header(self):
        """Create authentication header"""
        if DEMO_MODE:
            return {"Authorization": "Basic demo_auth"}
        
        auth_string = f"{self.username}:{self.api_key}"
        auth_bytes = auth_string.encode('ascii')
        auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
        return {"Authorization": f"Basic {auth_b64}"}
    
    def get_passive_dns(self, query):
        """Get passive DNS data"""
        if DEMO_MODE:
            return {
                "results": [
                    {
                        "resolve": "192.168.1.100",
                        "value": query,
                        "firstSeen": "2024-01-01",
                        "lastSeen": "2024-01-15",
                        "source": ["demo"]
                    }
                ],
                "totalRecords": 1
            }
        
        url = f"{self.base_url}dns/passive"
        headers = self.get_auth_header()
        params = {"query": query}
        
        try:
            response = requests.get(url, headers=headers, params=params)
            return response.json()
        except Exception as e:
            print(f"Error getting passive DNS: {e}")
            return None
    
    def get_whois_data(self, query):
        """Get WHOIS data"""
        if DEMO_MODE:
            return {
                "domain": query,
                "registrar": "Demo Registrar",
                "registrant": "Demo User",
                "registered": "2023-01-01",
                "expiresAt": "2025-01-01",
                "nameServers": ["ns1.demo.com", "ns2.demo.com"]
            }
        
        url = f"{self.base_url}whois"
        headers = self.get_auth_header()
        params = {"query": query}
        
        try:
            response = requests.get(url, headers=headers, params=params)
            return response.json()
        except Exception as e:
            print(f"Error getting WHOIS data: {e}")
            return None

if __name__ == "__main__":
    pt = PTAnalyzer()
    
    test_domain = "malicious-example.com"
    
    print("=== PassiveTotal Passive DNS ===")
    dns_result = pt.get_passive_dns(test_domain)
    if dns_result:
        print(f"Domain: {test_domain}")
        for record in dns_result.get("results", []):
            print(f"  Resolves to: {record.get('resolve')}")
            print(f"  First Seen: {record.get('firstSeen')}")
            print(f"  Last Seen: {record.get('lastSeen')}")
    
    print("\n=== PassiveTotal WHOIS ===")
    whois_result = pt.get_whois_data(test_domain)
    if whois_result:
        print(f"Domain: {test_domain}")
        print(f"Registrar: {whois_result.get('registrar')}")
        print(f"Registered: {whois_result.get('registered')}")
        print(f"Expires: {whois_result.get('expiresAt')}")
