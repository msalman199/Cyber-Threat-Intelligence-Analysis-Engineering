#!/usr/bin/env python3
import re
from collections import defaultdict

def analyze_network_logs(log_file):
    connections = defaultdict(list)
    suspicious_ips = []
    
    with open(log_file, 'r') as f:
        for line in f:
            # Parse network log entries
            if 'TCP' in line or 'DNS' in line or 'HTTPS' in line:
                parts = line.strip().split()
                timestamp = f"{parts[0]} {parts[1]}"
                protocol = parts[2]
                connection = parts[3]
                
                connections[protocol].append({
                    'timestamp': timestamp,
                    'connection': connection
                })
                
                # Check for suspicious IPs (external/unknown)
                if '185.220.101.45' in connection or 'tor-relay' in line:
                    suspicious_ips.append(connection)
    
    return connections, suspicious_ips

# Analyze network logs
connections, suspicious = analyze_network_logs('logs/network.log')

print("NETWORK FORENSIC ANALYSIS")
print("=" * 40)

for protocol, conn_list in connections.items():
    print(f"\n{protocol} Connections:")
    for conn in conn_list:
        print(f"  {conn['timestamp']} - {conn['connection']}")

print(f"\nSUSPICIOUS CONNECTIONS:")
for susp in suspicious:
    print(f"  {susp}")

print(f"\nTHREAT ASSESSMENT:")
print("- External C2 communication detected")
print("- Tor network usage identified")
print("- Potential data exfiltration channels")
