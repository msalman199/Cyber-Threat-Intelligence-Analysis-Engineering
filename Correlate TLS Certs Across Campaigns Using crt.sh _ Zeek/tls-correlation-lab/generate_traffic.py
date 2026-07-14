#!/usr/bin/env python3
import subprocess
import time

def generate_tls_connections():
    """Generate TLS connections to various sites"""
    sites = [
        "google.com",
        "github.com",
        "stackoverflow.com",
        "badssl.com",
        "expired.badssl.com"
    ]
    
    for site in sites:
        try:
            print(f"Connecting to {site}...")
            # Use curl to generate TLS traffic
            subprocess.run(['curl', '-s', '-m', '10', f'https://{site}'], 
                         capture_output=True, timeout=15)
            time.sleep(2)
        except Exception as e:
            print(f"Error connecting to {site}: {e}")

if __name__ == "__main__":
    generate_tls_connections()
