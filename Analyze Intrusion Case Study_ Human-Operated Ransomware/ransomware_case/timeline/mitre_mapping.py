#!/usr/bin/env python3
import json
import re

# Define observed techniques and their evidence
attack_mapping = {
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "evidence": "EventID:4624 Logon Type:3 Account:admin",
        "description": "Adversary used valid admin credentials"
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "evidence": "Remote logon from external IP",
        "description": "RDP used for initial access and lateral movement"
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "evidence": "powershell.exe -enc <base64>",
        "description": "Encoded PowerShell commands executed"
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "Impact",
        "evidence": "vssadmin.exe delete shadows, bcdedit /set recoveryenabled no",
        "description": "Deleted shadow copies and disabled recovery"
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "evidence": "encrypt.exe C:\\Users\\",
        "description": "File encryption process executed"
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "evidence": "HTTPS connections to 185.220.101.45",
        "description": "C2 communication over HTTPS"
    }
}

print("MITRE ATT&CK TECHNIQUE MAPPING")
print("=" * 50)
for technique_id, details in attack_mapping.items():
    print(f"\nTechnique ID: {technique_id}")
    print(f"Name: {details['name']}")
    print(f"Tactic: {details['tactic']}")
    print(f"Evidence: {details['evidence']}")
    print(f"Description: {details['description']}")
    print("-" * 30)
