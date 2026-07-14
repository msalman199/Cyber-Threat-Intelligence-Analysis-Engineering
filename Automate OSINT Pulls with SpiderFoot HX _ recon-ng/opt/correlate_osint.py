#!/usr/bin/env python3
import json
import csv
import sqlite3
import os
from datetime import datetime

class OSINTCorrelator:
    def __init__(self):
        self.spiderfoot_db = "/opt/spiderfoot/spiderfoot.db"
        self.reconng_db = "/opt/recon-ng/workspaces/osint_automation/data.db"
        self.output_file = "/opt/correlated_findings.json"
    
    def extract_spiderfoot_data(self):
        """Extract data from SpiderFoot database"""
        findings = []
        try:
            conn = sqlite3.connect(self.spiderfoot_db)
            cursor = conn.cursor()
            
            query = """
            SELECT scan_instance_id, data_type, data, source_data_type, 
                   source_data, created_time 
            FROM tbl_scan_results 
            ORDER BY created_time DESC LIMIT 100
            """
            
            cursor.execute(query)
            results = cursor.fetchall()
            
            for row in results:
                findings.append({
                    'tool': 'spiderfoot',
                    'scan_id': row[0],
                    'data_type': row[1],
                    'data': row[2],
                    'source_type': row[3],
                    'source_data': row[4],
                    'timestamp': row[5]
                })
            
            conn.close()
        except Exception as e:
            print(f"Error extracting SpiderFoot data: {e}")
        
        return findings
    
    def extract_reconng_data(self):
        """Extract data from recon-ng database"""
        findings = []
        try:
            conn = sqlite3.connect(self.reconng_db)
            cursor = conn.cursor()
            
            # Get hosts data
            cursor.execute("SELECT host, ip_address, region, country FROM hosts")
            hosts = cursor.fetchall()
            
            for host in hosts:
                findings.append({
                    'tool': 'recon-ng',
                    'data_type': 'host',
                    'hostname': host[0],
                    'ip_address': host[1],
                    'region': host[2],
                    'country': host[3],
                    'timestamp': datetime.now().isoformat()
                })
            
            conn.close()
        except Exception as e:
            print(f"Error extracting recon-ng data: {e}")
        
        return findings
    
    def correlate_findings(self, spiderfoot_data, reconng_data):
        """Correlate findings from both tools"""
        correlated = {
            'summary': {
                'spiderfoot_findings': len(spiderfoot_data),
                'reconng_findings': len(reconng_data),
                'correlation_timestamp': datetime.now().isoformat()
            },
            'ip_addresses': set(),
            'domains': set(),
            'emails': set(),
            'social_profiles': [],
            'vulnerabilities': [],
            'correlated_data': []
        }
        
        # Process SpiderFoot data
        for finding in spiderfoot_data:
            if 'IP_ADDRESS' in finding['data_type']:
                correlated['ip_addresses'].add(finding['data'])
            elif 'DOMAIN' in finding['data_type']:
                correlated['domains'].add(finding['data'])
            elif 'EMAIL' in finding['data_type']:
                correlated['emails'].add(finding['data'])
            elif 'SOCIAL' in finding['data_type']:
                correlated['social_profiles'].append(finding)
        
        # Process recon-ng data
        for finding in reconng_data:
            if finding['ip_address']:
                correlated['ip_addresses'].add(finding['ip_address'])
            if finding['hostname']:
                correlated['domains'].add(finding['hostname'])
        
        # Convert sets to lists for JSON serialization
        correlated['ip_addresses'] = list(correlated['ip_addresses'])
        correlated['domains'] = list(correlated['domains'])
        correlated['emails'] = list(correlated['emails'])
        
        return correlated
    
    def generate_report(self):
        """Generate comprehensive correlation report"""
        print("Extracting SpiderFoot data...")
        spiderfoot_data = self.extract_spiderfoot_data()
        
        print("Extracting recon-ng data...")
        reconng_data = self.extract_reconng_data()
        
        print("Correlating findings...")
        correlated = self.correlate_findings(spiderfoot_data, reconng_data)
        
        # Save to JSON file
        with open(self.output_file, 'w') as f:
            json.dump(correlated, f, indent=2, default=str)
        
        print(f"Correlation report saved to: {self.output_file}")
        return correlated

if __name__ == "__main__":
    correlator = OSINTCorrelator()
    results = correlator.generate_report()
    
    print("\n=== OSINT Correlation Summary ===")
    print(f"SpiderFoot findings: {results['summary']['spiderfoot_findings']}")
    print(f"recon-ng findings: {results['summary']['reconng_findings']}")
    print(f"Unique IP addresses: {len(results['ip_addresses'])}")
    print(f"Unique domains: {len(results['domains'])}")
    print(f"Email addresses found: {len(results['emails'])}")
