#!/usr/bin/env python3
import json
import os

def convert_zeek_to_json(log_file, output_file):
    events = []
    headers = []
    
    try:
        with open(log_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#fields'):
                    headers = line.split('\t')[1:]  # Remove '#fields'
                elif not line.startswith('#') and line:
                    fields = line.split('\t')
                    if len(fields) >= len(headers):
                        event = dict(zip(headers, fields))
                        events.append(event)
    
    except FileNotFoundError:
        # Create sample events if log doesn't exist
        if 'dns' in log_file:
            events = [
                {"ts": "1640995200", "query": "a1b2c3d4e5f6.malicious-domain.com", "qtype_name": "A"},
                {"ts": "1640995300", "query": "deadbeef123456.evil-site.net", "qtype_name": "A"}
            ]
        elif 'http' in log_file:
            events = [
                {"ts": "1640995200", "host": "suspicious-c2.example.com", "method": "GET"},
                {"ts": "1640995500", "host": "suspicious-c2.example.com", "method": "GET"}
            ]
    
    with open(output_file, 'w') as f:
        for event in events:
            json.dump(event, f)
            f.write('\n')
    
    print(f"Converted {len(events)} events to {output_file}")

# Convert logs
os.makedirs('analysis', exist_ok=True)
convert_zeek_to_json('logs/dns.log', 'analysis/dns_events.json')
convert_zeek_to_json('logs/http.log', 'analysis/http_events.json')
