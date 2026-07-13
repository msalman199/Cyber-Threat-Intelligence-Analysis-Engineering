#!/usr/bin/env python3

def map_attack_capabilities():
    capabilities = {
        "Initial Access": {
            "techniques": ["T1566.001 - Spearphishing Attachment"],
            "tools": ["Custom phishing framework"],
            "effectiveness": "High",
            "detection_difficulty": "Medium"
        },
        
        "Execution": {
            "techniques": ["T1059.001 - PowerShell", "T1204.002 - Malicious File"],
            "tools": ["PowerShell scripts", "Custom droppers"],
            "effectiveness": "High",
            "detection_difficulty": "Low to Medium"
        },
        
        "Persistence": {
            "techniques": ["T1547.001 - Registry Run Keys"],
            "tools": ["Registry modification tools"],
            "effectiveness": "Medium",
            "detection_difficulty": "Medium"
        },
        
        "Credential Access": {
            "techniques": ["T1003 - OS Credential Dumping"],
            "tools": ["Mimikatz", "Custom credential harvesters"],
            "effectiveness": "High",
            "detection_difficulty": "Medium"
        },
        
        "Command and Control": {
            "techniques": ["T1071.001 - Web Protocols"],
            "tools": ["Custom C2 framework"],
            "effectiveness": "High",
            "detection_difficulty": "High"
        }
    }
    
    return capabilities

def analyze_infrastructure():
    infrastructure = {
        "Command and Control": {
            "domains": [
                "fake-bank-update.com",
                "secure-finance.net",
                "banking-security.org"
            ],
            "ip_addresses": [
                "192.168.1.100",
                "10.0.0.50",
                "172.16.0.25"
            ],
            "hosting_providers": [
                "BulletproofHost LLC",
                "Anonymous Hosting Services"
            ]
        },
        
        "Delivery Infrastructure": {
            "email_servers": ["mail.fake-bank.com"],
            "compromised_sites": ["legitimate-site1.com", "news-portal.net"],
            "cdn_services": ["CloudFlare (abused)"]
        },
        
        "Operational Security": {
            "domain_registration": "Privacy protected",
            "ssl_certificates": "Let's Encrypt (automated)",
            "infrastructure_rotation": "Every 30-45 days"
        }
    }
    
    return infrastructure

def generate_capability_report():
    capabilities = map_attack_capabilities()
    infrastructure = analyze_infrastructure()
    
    report = "CAPABILITY AND INFRASTRUCTURE ANALYSIS\n"
    report += "="*50 + "\n\n"
    
    report += "ATTACK CAPABILITIES:\n"
    report += "-"*20 + "\n"
    for phase, details in capabilities.items():
        report += f"\n{phase}:\n"
        for key, value in details.items():
            if isinstance(value, list):
                report += f"  {key}: {', '.join(value)}\n"
            else:
                report += f"  {key}: {value}\n"
    
    report += "\n\nINFRASTRUCTURE ANALYSIS:\n"
    report += "-"*25 + "\n"
    for category, details in infrastructure.items():
        report += f"\n{category}:\n"
        for key, value in details.items():
            if isinstance(value, list):
                report += f"  {key}:\n"
                for item in value:
                    report += f"    • {item}\n"
            else:
                report += f"  {key}: {value}\n"
    
    return report

if __name__ == "__main__":
    report = generate_capability_report()
    print(report)
    
    # Save to file
    with open("../../reports/capability_infrastructure.txt", "w") as f:
        f.write(report)
