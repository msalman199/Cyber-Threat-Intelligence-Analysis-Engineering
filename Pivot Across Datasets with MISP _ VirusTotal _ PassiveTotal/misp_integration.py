#!/usr/bin/env python3
import json
import requests
from datetime import datetime

class MISPIntegration:
    def __init__(self):
        self.misp_url = "http://localhost/MISP"
        self.misp_key = "demo_key"  # In real scenario, use actual API key
        self.demo_mode = True
        
    def create_event(self, investigation_data):
        """Create MISP event from investigation data"""
        if self.demo_mode:
            print("=== Creating MISP Event (Demo Mode) ===")
            
            event_data = {
                "Event": {
                    "info": f"Threat Investigation: {investigation_data['initial_ioc']}",
                    "threat_level_id": "2",  # Medium
                    "analysis": "1",  # Ongoing
                    "distribution": "1",  # Community
                    "date": datetime.now().strftime("%Y-%m-%d"),
                    "Attribute": []
                }
            }
            
            # Add initial IOC as attribute
            event_data["Event"]["Attribute"].append({
                "category": "Network activity",
                "type": investigation_data["ioc_type"],
                "value": investigation_data["initial_ioc"],
                "to_ids": True,
                "comment": "Initial IOC from investigation"
            })
            
            # Add pivoted IOCs
            for pivot in investigation_data["pivot_chain"]:
                attr_type = self.determine_attribute_type(pivot["to"])
                if attr_type:
                    event_data["Event"]["Attribute"].append({
                        "category": "Network activity",
                        "type": attr_type,
                        "value": pivot["to"],
                        "to_ids": True,
                        "comment": f"Discovered via {pivot['method']} from {pivot['from']}"
                    })
            
            print(f"Event created with {len(event_data['Event']['Attribute'])} attributes")
            
            # Save event data
            with open(f"misp_event_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
                json.dump(event_data, f, indent=2)
            
            return event_data
        
        # Real MISP API call would go here
        return None
    
    def determine_attribute_type(self, value):
        """Determine MISP attribute type based on value"""
        if self.is_domain(value):
            return "domain"
        elif self.is_ip(value):
            return "ip-dst"
        elif self.is_url(value):
            return "url"
        elif self.is_hash(value):
            if len(value) == 32:
                return "md5"
            elif len(value) == 40:
                return "sha1"
            elif len(value) == 64:
                return "sha256"
        return None
    
    def is_domain(self, value):
        return '.' in value and not value.startswith('http') and not self.is_ip(value)
    
    def is_ip(self, value):
        parts = value.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def is_url(self, value):
        return value.startswith(('http://', 'https://'))
    
    def is_hash(self, value):
        return len(value) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in value)

if __name__ == "__main__":
    # Load investigation data
    import glob
    report_files = glob.glob("investigation_report_*.json")
    
    if report_files:
        latest_report = max(report_files)
        with open(latest_report, 'r') as f:
            investigation_data = json.load(f)
        
        misp = MISPIntegration()
        event = misp.create_event(investigation_data)
        
        print(f"MISP event created from {latest_report}")
    else:
        print("No investigation reports found. Run pivot_engine.py first.")
