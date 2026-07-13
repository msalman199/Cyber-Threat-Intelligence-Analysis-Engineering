#!/usr/bin/env python3
from datetime import datetime

timeline_events = [
    ("2024-01-15 08:30:15", "T1078", "Initial Access", "Admin account logon from external IP"),
    ("2024-01-15 08:31:22", "T1078", "Credential Access", "Explicit credential use detected"),
    ("2024-01-15 08:32:45", "T1078", "Privilege Escalation", "Special privileges assigned"),
    ("2024-01-15 08:35:10", "T1059.001", "Execution", "PowerShell with encoded commands"),
    ("2024-01-15 08:36:30", "T1490", "Impact", "Shadow copy deletion initiated"),
    ("2024-01-15 08:37:15", "T1490", "Impact", "All shadow copies deleted"),
    ("2024-01-15 08:40:00", "T1490", "Impact", "System recovery disabled"),
    ("2024-01-15 09:15:30", "T1486", "Impact", "File encryption process started")
]

print("ATTACK TIMELINE WITH MITRE ATT&CK MAPPING")
print("=" * 60)
for timestamp, technique, tactic, description in timeline_events:
    print(f"{timestamp} | {technique:10} | {tactic:15} | {description}")
