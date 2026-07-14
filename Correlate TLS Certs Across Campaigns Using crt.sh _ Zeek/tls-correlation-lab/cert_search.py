#!/usr/bin/env python3
import requests
import json
import sys
import time

def search_crtsh(domain, output_file):
    """Search crt.sh for certificates associated with a domain"""
    url = f"https://crt.sh/?q={domain}&output=json"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        certs = response.json()
        print(f"Found {len(certs)} certificates for {domain}")
        
        # Save raw data
        with open(f"certs/{output_file}", 'w') as f:
            json.dump(certs, f, indent=2)
            
        return certs
    except Exception as e:
        print(f"Error searching for {domain}: {e}")
        return []

def extract_cert_details(certs, domain):
    """Extract relevant certificate details"""
    cert_details = []
    
    for cert in certs:
        detail = {
            'id': cert.get('id'),
            'logged_at': cert.get('entry_timestamp'),
            'not_before': cert.get('not_before'),
            'not_after': cert.get('not_after'),
            'common_name': cert.get('common_name'),
            'name_value': cert.get('name_value'),
            'issuer_name': cert.get('issuer_name'),
            'serial_number': cert.get('serial_number'),
            'domain_searched': domain
        }
        cert_details.append(detail)
    
    return cert_details

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 cert_search.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    output_file = f"{domain.replace('.', '_')}_certs.json"
    
    certs = search_crtsh(domain, output_file)
    if certs:
        details = extract_cert_details(certs, domain)
        
        # Save processed details
        with open(f"analysis/{domain.replace('.', '_')}_details.json", 'w') as f:
            json.dump(details, f, indent=2)
        
        print(f"Certificate details saved to analysis/{domain.replace('.', '_')}_details.json")
