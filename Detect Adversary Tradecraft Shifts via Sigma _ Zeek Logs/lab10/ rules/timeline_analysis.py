#!/usr/bin/env python3
import json
import datetime
from collections import defaultdict

def create_timeline():
    timeline = defaultdict(list)
    
    # Simulate different time periods with evolving tradecraft
    periods = {
        "2024-01-01": {
            "dns_queries": ["short-domain.com", "normal-site.net"],
            "http_hosts": ["legitimate-site.com"],
            "techniques": ["Basic DNS queries", "Standard HTTP requests"]
        },
        "2024-01-15": {
            "dns_queries": ["a1b2c3d4e5f6.malicious-domain.com", "longer-suspicious-domain-name.evil.net"],
            "http_hosts": ["suspicious-c2.example.com"],
            "techniques": ["DNS tunneling emergence", "C2 beaconing starts"]
        },
        "2024-02-01": {
            "dns_queries": ["deadbeef123456789abcdef.advanced-exfil.org", "x9y8z7w6v5u4t3s2r1.steganography.net"],
            "http_hosts": ["malware-command.example.net", "backdoor-control.example.org"],
            "techniques": ["Advanced DNS exfiltration", "Multi-channel C2", "Evasion techniques"]
        }
    }
    
    print("=== ADVERSARY TRADECRAFT EVOLUTION TIMELINE ===\n")
    
    for date, data in periods.items():
        print(f"📅 {date}")
        print(f"   Techniques Observed: {', '.join(data['techniques'])}")
        print(f"   DNS Patterns: {len(data['dns_queries'])} unique queries")
        for query in data['dns_queries'][:3]:  # Show first 3
            print(f"     - {query}")
        print(f"   HTTP Targets: {len(data['http_hosts'])} hosts")
        for host in data['http_hosts']:
            print(f"     - {host}")
        print()
    
    # Analyze evolution patterns
    print("=== TRADECRAFT SHIFT ANALYSIS ===")
    print("1. DNS Query Evolution:")
    print("   - Week 1: Standard domain lengths (10-20 chars)")
    print("   - Week 3: Extended domains for tunneling (30-50 chars)")
    print("   - Week 6: Hex-encoded data exfiltration (50+ chars)")
    
    print("\n2. C2 Infrastructure Changes:")
    print("   - Week 1: Single legitimate-looking domain")
    print("   - Week 3: Dedicated C2 infrastructure")
    print("   - Week 6: Multi-channel redundant C2")
    
    print("\n3. Evasion Technique Progression:")
    print("   - Week 1: No evasion (baseline activity)")
    print("   - Week 3: Domain generation algorithms")
    print("   - Week 6: Steganography and advanced encoding")

def detect_shifts():
    print("\n=== SHIFT DETECTION INDICATORS ===")
    
    indicators = [
        {
            "metric": "Average DNS Query Length",
            "week1": 15.2,
            "week3": 35.7,
            "week6": 52.3,
            "threshold": 25.0,
            "shift_detected": True
        },
        {
            "metric": "HTTP Request Frequency",
            "week1": 0.1,  # requests per minute
            "week3": 0.2,
            "week6": 0.33,
            "threshold": 0.25,
            "shift_detected": True
        },
        {
            "metric": "Unique C2 Domains",
            "week1": 1,
            "week3": 1,
            "week6": 3,
            "threshold": 2,
            "shift_detected": True
        }
    ]
    
    for indicator in indicators:
        print(f"\n📊 {indicator['metric']}:")
        print(f"   Week 1: {indicator['week1']}")
        print(f"   Week 3: {indicator['week3']}")
        print(f"   Week 6: {indicator['week6']}")
        print(f"   Threshold: {indicator['threshold']}")
        
        if indicator['shift_detected']:
            print("   🚨 TRADECRAFT SHIFT DETECTED")
            
            # Calculate percentage change
            change_3_to_6 = ((indicator['week6'] - indicator['week3']) / indicator['week3']) * 100
            print(f"   📈 Change from Week 3 to 6: {change_3_to_6:.1f}%")
        else:
            print("   ✅ No significant shift detected")

if __name__ == "__main__":
    create_timeline()
    detect_shifts()
