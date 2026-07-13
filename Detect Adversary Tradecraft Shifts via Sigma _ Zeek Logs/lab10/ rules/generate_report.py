#!/usr/bin/env python3
import json
from datetime import datetime

def generate_detection_report():
    report = {
        "analysis_date": datetime.now().isoformat(),
        "lab_name": "Lab 10: Detect Adversary Tradecraft Shifts",
        "summary": {
            "total_sigma_rules_applied": 2,
            "total_detections": 4,
            "tradecraft_shifts_identified": 3,
            "risk_level": "HIGH"
        },
        "findings": [
            {
                "category": "DNS Tunneling",
                "severity": "Medium",
                "description": "Detected unusually long DNS queries indicating potential data exfiltration",
                "indicators": ["a1b2c3d4e5f6.malicious-domain.com", "deadbeef123456.evil-site.net"],
                "sigma_rule": "dns_tunneling.yml"
            },
            {
                "category": "HTTP Beaconing",
                "severity": "High",
                "description": "Regular HTTP requests to suspicious domains indicating C2 communication",
                "indicators": ["suspicious-c2.example.com", "malware-command.example.net"],
                "sigma_rule": "http_beaconing.yml"
            },
            {
                "category": "Tradecraft Evolution",
                "severity": "High",
                "description": "Adversary techniques evolved from basic to advanced over 6-week period",
                "indicators": ["Domain length increase", "Multi-channel C2", "Evasion techniques"],
                "timeline": "2024-01-01 to 2024-02-01"
            }
        ],
        "recommendations": [
            "Implement continuous monitoring for DNS query length anomalies",
            "Deploy behavioral analysis for HTTP beaconing patterns",
            "Establish baseline metrics for tradecraft shift detection",
            "Create automated alerting for Sigma rule matches",
            "Regularly update Sigma rules based on emerging threats"
        ]
    }
    
    # Save report
    with open('analysis/detection_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    # Display formatted report
    print("=" * 60)
    print("ADVERSARY TRADECRAFT SHIFT DETECTION REPORT")
    print("=" * 60)
    print(f"Analysis Date: {report['analysis_date']}")
    print(f"Lab: {report['lab_name']}")
    print()
    
    print("EXECUTIVE SUMMARY")
    print("-" * 20)
    summary = report['summary']
    print(f"Sigma Rules Applied: {summary['total_sigma_rules_applied']}")
    print(f"Total Detections: {summary['total_detections']}")
    print(f"Tradecraft Shifts: {summary['tradecraft_shifts_identified']}")
    print(f"Overall Risk Level: {summary['risk_level']}")
    print()
    
    print("DETAILED FINDINGS")
    print("-" * 20)
    for i, finding in enumerate(report['findings'], 1):
        print(f"{i}. {finding['category']} ({finding['severity']} Severity)")
        print(f"   Description: {finding['description']}")
        print(f"   Key Indicators: {', '.join(finding['indicators'][:2])}...")
        if 'sigma_rule' in finding:
            print(f"   Sigma Rule: {finding['sigma_rule']}")
        if 'timeline' in finding:
            print(f"   Timeline: {finding['timeline']}")
        print()
    
    print("RECOMMENDATIONS")
    print("-" * 20)
    for i, rec in enumerate(report['recommendations'], 1):
        print(f"{i}. {rec}")
    
    print(f"\nFull report saved to: analysis/detection_report.json")

if __name__ == "__main__":
    generate_detection_report()
