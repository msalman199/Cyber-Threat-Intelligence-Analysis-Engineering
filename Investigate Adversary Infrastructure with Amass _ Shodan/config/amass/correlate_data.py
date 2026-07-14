#!/usr/bin/env python3
import csv
import subprocess
import json
import time

def get_shodan_info(ip):
    try:
        result = subprocess.run(['shodan', 'host', ip], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return result.stdout
        return None
    except:
        return None

print("Domain,IP,Shodan_Info")
with open('domain_ip_mapping.csv', 'r') as f:
    for line in f:
        if ',' in line:
            domain, ip = line.strip().split(',', 1)
            shodan_info = get_shodan_info(ip)
            if shodan_info:
                # Extract key information
                lines = shodan_info.split('\n')
                ports = [l for l in lines if 'Ports:' in l]
                org = [l for l in lines if 'Organization:' in l]
                
                info_summary = f"Ports: {ports[0] if ports else 'N/A'} | Org: {org[0] if org else 'N/A'}"
                print(f"{domain},{ip},{info_summary}")
            else:
                print(f"{domain},{ip},No Shodan data")
            time.sleep(1)  # Rate limiting
