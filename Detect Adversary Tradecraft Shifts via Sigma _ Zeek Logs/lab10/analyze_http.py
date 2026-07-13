#!/usr/bin/env python3
from collections import defaultdict
import datetime

def analyze_http_logs():
    connections = defaultdict(list)
    suspicious_hosts = []
    
    try:
        with open('logs/http.log', 'r') as f:
            for line in f:
                if line.startswith('#') or not line.strip():
                    continue
                
                fields = line.strip().split('\t')
                if len(fields) >= 9:
                    timestamp = float(fields[0])
                    host = fields[8] if len(fields) > 8 else "unknown"
                    connections[host].append(timestamp)
    
    except FileNotFoundError:
        print("HTTP log not found, using sample data...")
        # Simulate beaconing pattern
        connections = {
            "suspicious-c2.example.com": [1640995200, 1640995500, 1640995800],
            "malware-command.example.net": [1640995300, 1640995600, 1640995900]
        }
    
    print("=== HTTP Beaconing Analysis ===")
    for host, timestamps in connections.items():
        if len(timestamps) >= 3:
            intervals = []
            for i in range(1, len(timestamps)):
                intervals.append(timestamps[i] - timestamps[i-1])
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                
                # Low variance indicates regular beaconing
                if variance < 100 and len(timestamps) >= 3:
                    suspicious_hosts.append({
                        'host': host,
                        'connections': len(timestamps),
                        'avg_interval': avg_interval,
                        'variance': variance
                    })
    
    print(f"Potential beaconing hosts: {len(suspicious_hosts)}")
    for host_info in suspicious_hosts:
        print(f"  - {host_info['host']}: {host_info['connections']} connections, "
              f"avg interval: {host_info['avg_interval']:.1f}s")

if __name__ == "__main__":
    analyze_http_logs()
