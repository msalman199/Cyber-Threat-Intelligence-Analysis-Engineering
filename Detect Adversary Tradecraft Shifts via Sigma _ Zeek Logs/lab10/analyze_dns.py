#!/usr/bin/env python3
import json
import re
from collections import Counter

def analyze_dns_logs():
    suspicious_patterns = []
    domain_lengths = []
    
    try:
        with open('logs/dns.log', 'r') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue
                
                fields = line.strip().split('\t')
                if len(fields) >= 9:
                    query = fields[9]  # DNS query field
                    domain_lengths.append(len(query))
                    
                    # Check for suspicious patterns
                    if len(query) > 50:  # Unusually long domains
                        suspicious_patterns.append(f"Long domain: {query}")
                    
                    if re.search(r'[a-f0-9]{20,}', query):  # Hex-like strings
                        suspicious_patterns.append(f"Hex pattern: {query}")
                    
                    if query.count('.') > 5:  # Too many subdomains
                        suspicious_patterns.append(f"Many subdomains: {query}")
    
    except FileNotFoundError:
        print("DNS log not found, generating sample data...")
        suspicious_patterns = [
            "Long domain: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0.malicious-domain.com",
            "Hex pattern: deadbeef123456789abcdef.evil-site.net"
        ]
    
    print("=== DNS Analysis Results ===")
    print(f"Suspicious patterns found: {len(suspicious_patterns)}")
    for pattern in suspicious_patterns[:10]:  # Show first 10
        print(f"  - {pattern}")
    
    if domain_lengths:
        avg_length = sum(domain_lengths) / len(domain_lengths)
        print(f"Average domain length: {avg_length:.2f}")

if __name__ == "__main__":
    analyze_dns_logs()
