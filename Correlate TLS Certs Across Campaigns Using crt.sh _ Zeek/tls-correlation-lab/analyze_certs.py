#!/usr/bin/env python3
import json
import os
from collections import defaultdict
import pandas as pd

def load_cert_data():
    """Load all certificate data from analysis directory"""
    cert_data = []
    
    for filename in os.listdir('analysis'):
        if filename.endswith('_details.json'):
            with open(f'analysis/{filename}', 'r') as f:
                data = json.load(f)
                cert_data.extend(data)
    
    return cert_data

def find_common_issuers(cert_data):
    """Find common certificate issuers across campaigns"""
    issuer_count = defaultdict(list)
    
    for cert in cert_data:
        issuer = cert.get('issuer_name', 'Unknown')
        domain = cert.get('domain_searched', 'Unknown')
        issuer_count[issuer].append(domain)
    
    return issuer_count

def find_serial_patterns(cert_data):
    """Look for patterns in certificate serial numbers"""
    serial_patterns = defaultdict(list)
    
    for cert in cert_data:
        serial = cert.get('serial_number', '')
        if serial:
            # Group by first few characters of serial number
            pattern = serial[:8] if len(serial) >= 8 else serial
            serial_patterns[pattern].append({
                'domain': cert.get('domain_searched'),
                'full_serial': serial,
                'issuer': cert.get('issuer_name')
            })
    
    return serial_patterns

def analyze_time_correlation(cert_data):
    """Analyze certificate issuance timing"""
    df = pd.DataFrame(cert_data)
    df['not_before'] = pd.to_datetime(df['not_before'])
    
    # Group by domain and analyze timing
    timing_analysis = df.groupby('domain_searched')['not_before'].agg(['min', 'max', 'count'])
    
    return timing_analysis

if __name__ == "__main__":
    print("Loading certificate data...")
    cert_data = load_cert_data()
    print(f"Loaded {len(cert_data)} certificates")
    
    print("\n=== Common Issuers Analysis ===")
    issuers = find_common_issuers(cert_data)
    for issuer, domains in issuers.items():
        if len(set(domains)) > 1:  # Issuer used by multiple domains
            print(f"Issuer: {issuer}")
            print(f"  Domains: {set(domains)}")
    
    print("\n=== Serial Number Patterns ===")
    patterns = find_serial_patterns(cert_data)
    for pattern, certs in patterns.items():
        if len(certs) > 1:
            print(f"Pattern: {pattern}")
            for cert in certs:
                print(f"  {cert['domain']} - {cert['issuer']}")
    
    print("\n=== Timing Analysis ===")
    timing = analyze_time_correlation(cert_data)
    print(timing)
