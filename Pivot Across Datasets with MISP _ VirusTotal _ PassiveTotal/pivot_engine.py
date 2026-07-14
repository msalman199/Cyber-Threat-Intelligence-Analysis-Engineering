#!/usr/bin/env python3
import json
from datetime import datetime
from vt_analyzer import VTAnalyzer
from pt_analyzer import PTAnalyzer

class PivotEngine:
    def __init__(self):
        self.vt = VTAnalyzer()
        self.pt = PTAnalyzer()
        self.investigation_data = {}
        
    def start_investigation(self, initial_ioc, ioc_type):
        """Start investigation with initial IOC"""
        print(f"=== Starting Investigation ===")
        print(f"Initial IOC: {initial_ioc} (Type: {ioc_type})")
        
        self.investigation_data = {
            "initial_ioc": initial_ioc,
            "ioc_type": ioc_type,
            "timestamp": datetime.now().isoformat(),
            "findings": {},
            "pivot_chain": []
        }
        
        if ioc_type == "domain":
            self.investigate_domain(initial_ioc)
        elif ioc_type == "hash":
            self.investigate_hash(initial_ioc)
        elif ioc_type == "ip":
            self.investigate_ip(initial_ioc)
    
    def investigate_domain(self, domain):
        """Comprehensive domain investigation"""
        print(f"\n=== Investigating Domain: {domain} ===")
        
        # VirusTotal Analysis
        vt_result = self.vt.analyze_domain(domain)
        if vt_result:
            self.investigation_data["findings"][f"vt_domain_{domain}"] = vt_result
            print(f"VT Detections: {vt_result.get('positives', 0)}/{vt_result.get('total', 0)}")
            
            # Pivot to detected URLs
            detected_urls = vt_result.get("detected_urls", [])
            for url_data in detected_urls[:3]:  # Limit to first 3
                url = url_data.get("url", "")
                print(f"  Detected URL: {url}")
                self.investigation_data["pivot_chain"].append({
                    "from": domain,
                    "to": url,
                    "method": "VT_detected_urls",
                    "timestamp": datetime.now().isoformat()
                })
        
        # PassiveTotal Analysis
        pt_dns = self.pt.get_passive_dns(domain)
        if pt_dns:
            self.investigation_data["findings"][f"pt_dns_{domain}"] = pt_dns
            print(f"PT DNS Records: {pt_dns.get('totalRecords', 0)}")
            
            # Pivot to resolved IPs
            for record in pt_dns.get("results", [])[:3]:  # Limit to first 3
                ip = record.get("resolve", "")
                if ip and self.is_valid_ip(ip):
                    print(f"  Resolves to IP: {ip}")
                    self.investigation_data["pivot_chain"].append({
                        "from": domain,
                        "to": ip,
                        "method": "PT_passive_dns",
                        "first_seen": record.get("firstSeen"),
                        "last_seen": record.get("lastSeen")
                    })
                    # Continue investigation with IP
                    self.investigate_ip(ip)
        
        # WHOIS Analysis
        whois_data = self.pt.get_whois_data(domain)
        if whois_data:
            self.investigation_data["findings"][f"pt_whois_{domain}"] = whois_data
            print(f"Registrar: {whois_data.get('registrar', 'N/A')}")
            
            # Pivot to name servers
            name_servers = whois_data.get("nameServers", [])
            for ns in name_servers[:2]:  # Limit to first 2
                print(f"  Name Server: {ns}")
                self.investigation_data["pivot_chain"].append({
                    "from": domain,
                    "to": ns,
                    "method": "WHOIS_nameservers",
                    "timestamp": datetime.now().isoformat()
                })
    
    def investigate_hash(self, file_hash):
        """Investigate file hash"""
        print(f"\n=== Investigating Hash: {file_hash} ===")
        
        vt_result = self.vt.analyze_hash(file_hash)
        if vt_result:
            self.investigation_data["findings"][f"vt_hash_{file_hash}"] = vt_result
            print(f"VT Detections: {vt_result.get('positives', 0)}/{vt_result.get('total', 0)}")
            
            # In a real scenario, you would extract domains/IPs from the analysis
            # For demo, we'll simulate finding related domains
            related_domains = ["related-malware.com", "c2-server.net"]
            for domain in related_domains:
                print(f"  Related Domain Found: {domain}")
                self.investigation_data["pivot_chain"].append({
                    "from": file_hash,
                    "to": domain,
                    "method": "VT_hash_analysis",
                    "timestamp": datetime.now().isoformat()
                })
                self.investigate_domain(domain)
    
    def investigate_ip(self, ip):
        """Investigate IP address"""
        print(f"\n=== Investigating IP: {ip} ===")
        
        # Get reverse DNS from PassiveTotal
        pt_dns = self.pt.get_passive_dns(ip)
        if pt_dns:
            self.investigation_data["findings"][f"pt_reverse_dns_{ip}"] = pt_dns
            print(f"Reverse DNS Records: {pt_dns.get('totalRecords', 0)}")
            
            for record in pt_dns.get("results", [])[:2]:  # Limit to first 2
                domain = record.get("value", "")
                if domain:
                    print(f"  Reverse resolves to: {domain}")
                    self.investigation_data["pivot_chain"].append({
                        "from": ip,
                        "to": domain,
                        "method": "PT_reverse_dns",
                        "first_seen": record.get("firstSeen"),
                        "last_seen": record.get("lastSeen")
                    })
    
    def is_valid_ip(self, ip):
        """Basic IP validation"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def generate_report(self):
        """Generate investigation report"""
        print(f"\n=== Investigation Report ===")
        print(f"Initial IOC: {self.investigation_data['initial_ioc']}")
        print(f"Investigation Started: {self.investigation_data['timestamp']}")
        print(f"Total Findings: {len(self.investigation_data['findings'])}")
        print(f"Pivot Chain Length: {len(self.investigation_data['pivot_chain'])}")
        
        print(f"\n=== Pivot Chain ===")
        for i, pivot in enumerate(self.investigation_data['pivot_chain'], 1):
            print(f"{i}. {pivot['from']} -> {pivot['to']} (via {pivot['method']})")
        
        # Save report to file
        with open(f"investigation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", 'w') as f:
            json.dump(self.investigation_data, f, indent=2)
        
        print(f"\nReport saved to investigation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

if __name__ == "__main__":
    engine = PivotEngine()
    
    # Start investigation with a suspicious domain
    engine.start_investigation("malicious-example.com", "domain")
    
    # Generate final report
    engine.generate_report()
