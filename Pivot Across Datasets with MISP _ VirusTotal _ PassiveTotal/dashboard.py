#!/usr/bin/env python3
import json
import glob
from datetime import datetime

def display_dashboard():
    """Display investigation dashboard"""
    print("=" * 60)
    print("THREAT INTELLIGENCE INVESTIGATION DASHBOARD")
    print("=" * 60)
    
    # Load latest investigation
    report_files = glob.glob("investigation_report_*.json")
    if not report_files:
        print("No investigations found.")
        return
    
    latest_report = max(report_files)
    with open(latest_report, 'r') as f:
        data = json.load(f)
    
    print(f"\nLatest Investigation: {latest_report}")
    print(f"Initial IOC: {data['initial_ioc']} ({data['ioc_type']})")
    print(f"Started: {data['timestamp']}")
    print(f"Total Findings: {len(data['findings'])}")
    print(f"Pivot Operations: {len(data['pivot_chain'])}")
    
    print(f"\n{'='*20} PIVOT CHAIN {'='*20}")
    for i, pivot in enumerate(data['pivot_chain'], 1):
        print(f"{i:2d}. {pivot['from']:<25} -> {pivot['to']:<25} [{pivot['method']}]")
    
    print(f"\n{'='*20} DATA SOURCES {'='*20}")
    vt_findings = sum(1 for key in data['findings'].keys() if key.startswith('vt_'))
    pt_findings = sum(1 for key in data['findings'].keys() if key.startswith('pt_'))
    
    print(f"VirusTotal Queries: {vt_findings}")
    print(f"PassiveTotal Queries: {pt_findings}")
    
    print(f"\n{'='*20} THREAT SUMMARY {'='*20}")
    
    # Analyze findings for threat indicators
    domains_found = set()
    ips_found = set()
    
    for pivot in data['pivot_chain']:
        if '.' in pivot['to'] and not pivot['to'].startswith('http'):
            if any(char.isalpha() for char in pivot['to']):
                domains_found.add(pivot['to'])
            else:
                try:
                    parts = pivot['to'].split('.')
                    if len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts):
                        ips_found.add(pivot['to'])
                except:
                    pass
    
    print(f"Unique Domains Discovered: {len(domains_found)}")
    print(f"Unique IPs Discovered: {len(ips_found)}")
    
    if domains_found:
        print(f"\nDomains:")
        for domain in sorted(domains_found):
            print(f"  - {domain}")
    
    if ips_found:
        print(f"\nIP Addresses:")
        for ip in sorted(ips_found):
            print(f"  - {ip}")
    
    print(f"\n{'='*60}")

if __name__ == "__main__":
    display_dashboard()
