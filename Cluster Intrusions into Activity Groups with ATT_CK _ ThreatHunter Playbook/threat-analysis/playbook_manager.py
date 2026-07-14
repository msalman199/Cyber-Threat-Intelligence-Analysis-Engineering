#!/usr/bin/env python3
import json
import os
from datetime import datetime
import uuid

class ThreatHunterPlaybook:
    def __init__(self, base_dir="playbooks"):
        self.base_dir = base_dir
        self.template_dir = os.path.join(base_dir, "templates")
        self.active_dir = os.path.join(base_dir, "active")
        self.completed_dir = os.path.join(base_dir, "completed")
    
    def create_playbook(self, activity_group, hypothesis, techniques):
        """Create new threat hunting playbook"""
        playbook_id = str(uuid.uuid4())[:8]
        
        # Load template
        with open(os.path.join(self.template_dir, "activity_group_template.json"), 'r') as f:
            playbook = json.load(f)
        
        # Fill template
        playbook.update({
            "playbook_id": playbook_id,
            "activity_group": activity_group,
            "creation_date": datetime.now().isoformat(),
            "hypothesis": hypothesis,
            "techniques_observed": techniques
        })
        
        # Save active playbook
        filename = f"{activity_group}_{playbook_id}.json"
        filepath = os.path.join(self.active_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(playbook, f, indent=2)
        
        print(f"Created playbook: {filename}")
        return playbook_id
    
    def update_playbook(self, playbook_id, updates):
        """Update existing playbook"""
        # Find playbook file
        for filename in os.listdir(self.active_dir):
            if playbook_id in filename:
                filepath = os.path.join(self.active_dir, filename)
                
                with open(filepath, 'r') as f:
                    playbook = json.load(f)
                
                playbook.update(updates)
                
                with open(filepath, 'w') as f:
                    json.dump(playbook, f, indent=2)
                
                print(f"Updated playbook: {filename}")
                return True
        
        print(f"Playbook {playbook_id} not found")
        return False
    
    def list_active_playbooks(self):
        """List all active playbooks"""
        print("=== ACTIVE THREAT HUNTING PLAYBOOKS ===\n")
        
        for filename in os.listdir(self.active_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.active_dir, filename)
                
                with open(filepath, 'r') as f:
                    playbook = json.load(f)
                
                print(f"ID: {playbook['playbook_id']}")
                print(f"Group: {playbook['activity_group']}")
                print(f"Status: {playbook['status']}")
                print(f"Hypothesis: {playbook['hypothesis']}")
                print(f"Techniques: {', '.join(playbook['techniques_observed'])}")
                print("-" * 50)

def main():
    # Initialize playbook manager
    pb_manager = ThreatHunterPlaybook()
    
    # Create playbooks based on clustering results
    print("Creating threat hunting playbooks...\n")
    
    # Cluster 0 - Financial sector attacks
    pb_id1 = pb_manager.create_playbook(
        activity_group="APT-Financial-001",
        hypothesis="Coordinated spear-phishing campaign targeting financial institutions",
        techniques=["T1566.001", "T1059.001", "T1055", "T1083"]
    )
    
    # Cluster 1 - Web-based attacks
    pb_id2 = pb_manager.create_playbook(
        activity_group="WebShell-Group-001", 
        hypothesis="Web application exploitation for persistent access",
        techniques=["T1190", "T1505.003", "T1083", "T1041"]
    )
    
    # Update playbooks with additional evidence
    pb_manager.update_playbook(pb_id1, {
        "indicators": ["192.168.1.100", "malicious.exe", "suspicious.dll"],
        "confidence_level": "Medium",
        "evidence": ["Multiple intrusions from same IP", "Similar malware families"]
    })
    
    pb_manager.update_playbook(pb_id2, {
        "indicators": ["10.0.0.50", "webshell.php", "data.zip"],
        "confidence_level": "High", 
        "evidence": ["Web shell deployment", "Data exfiltration patterns"]
    })
    
    # List all active playbooks
    pb_manager.list_active_playbooks()

if __name__ == "__main__":
    main()
