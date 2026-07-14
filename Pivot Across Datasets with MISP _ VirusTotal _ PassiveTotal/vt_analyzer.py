#!/usr/bin/env python3
import requests
import json
import time
from api_config import VT_API_KEY, DEMO_MODE

class VTAnalyzer:
    def __init__(self):
        self.api_key = VT_API_KEY
        self.base_url = "https://www.virustotal.com/vtapi/v2/"
        
    def analyze_hash(self, file_hash):
        """Analyze file hash using VirusTotal"""
        if DEMO_MODE:
            # Return demo data for educational purposes
            return {
                "response_code": 1,
                "positives": 15,
                "total": 70,
                "scan_date": "2024-01-15 10:30:00",
                "permalink": f"https://www.virustotal.com/file/{file_hash}/analysis/",
                "md5": file_hash[:32] if len(file_hash) > 32 else file_hash
            }
        
        url = f"{self.base_url}file/report"
        params = {
            'apikey': self.api_key,
            'resource': file_hash
        }
        
        try:
            response = requests.get(url, params=params)
            return response.json()
        except Exception as e:
            print(f"Error analyzing hash: {e}")
            return None
    
    def analyze_domain(self, domain):
        """Analyze domain using VirusTotal"""
        if DEMO_MODE:
            return {
                "response_code": 1,
                "positives": 3,
                "total": 70,
                "scan_date": "2024-01-15 10:30:00",
                "domain": domain,
                "detected_urls": [
                    {"url": f"http://{domain}/malware.exe", "positives": 12, "total": 70}
                ]
            }
        
        url = f"{self.base_url}domain/report"
        params = {
            'apikey': self.api_key,
            'domain': domain
        }
        
        try:
            response = requests.get(url, params=params)
            return response.json()
        except Exception as e:
            print(f"Error analyzing domain: {e}")
            return None

if __name__ == "__main__":
    vt = VTAnalyzer()
    
    # Test with sample indicators
    test_hash = "44d88612fea8a8f36de82e1278abb02f"
    test_domain = "malicious-example.com"
    
    print("=== VirusTotal Hash Analysis ===")
    hash_result = vt.analyze_hash(test_hash)
    if hash_result:
        print(f"Hash: {test_hash}")
        print(f"Detections: {hash_result.get('positives', 0)}/{hash_result.get('total', 0)}")
        print(f"Scan Date: {hash_result.get('scan_date', 'N/A')}")
    
    print("\n=== VirusTotal Domain Analysis ===")
    domain_result = vt.analyze_domain(test_domain)
    if domain_result:
        print(f"Domain: {test_domain}")
        print(f"Detections: {domain_result.get('positives', 0)}/{domain_result.get('total', 0)}")
