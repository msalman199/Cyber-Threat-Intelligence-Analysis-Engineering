#!/usr/bin/env python3

import json
import pandas as pd
from collections import Counter
from intel_enricher import IntelligenceEnricher
import matplotlib.pyplot as plt

class IntelligenceAnalyzer:
    def __init__(self):
        self.enricher = IntelligenceEnricher()
    
    def analyze_threat_patterns(self, enriched_data):
        """Analyze patterns in enriched threat intelligence"""
        analysis_results = {
            'ioc_summary': {},
            'threat_levels': {},
            'recommendations': []
        }
        
        # Count IOCs by type
        for ioc_type, ioc_list in enriched_data.items():
            analysis_results['ioc_summary'][ioc_type] = len(ioc_list)
            
            # Analyze threat levels
            threat_levels = [ioc.get('threat_level', 'Unknown') for ioc in ioc_list]
            analysis_results['threat_levels'][ioc_type] = Counter(threat_levels)
        
        # Generate recommendations
        total_known_threats = sum(
            counts.get('Known threat', 0) 
            for counts in analysis_results['threat_levels'].values()
        )
        
        if total_known_threats > 0:
            analysis_results['recommendations'].append(
                f"HIGH PRIORITY: {total_known_threats} known threats detected - immediate investigation required"
            )
        
        unknown_threats = sum(
            counts.get('Unknown', 0) 
            for counts in analysis_results['threat_levels'].values()
        )
        
        if unknown_threats > 5:
            analysis_results['recommendations'].append(
                f"MEDIUM PRIORITY: {unknown_threats} unknown IOCs require further analysis"
            )
        
        return analysis_results
    
    def generate_report(self, analysis_results):
        """Generate a comprehensive threat intelligence report"""
        report = []
        report.append("=" * 60)
        report.append("THREAT INTELLIGENCE ANALYSIS REPORT")
        report.append("=" * 60)
        
        # IOC Summary
        report.append("\n📊 IOC SUMMARY:")
        for ioc_type, count in analysis_results['ioc_summary'].items():
            report.append(f"  {ioc_type.upper()}: {count}")
        
        # Threat Level Analysis
        report.append("\n🚨 THREAT LEVEL BREAKDOWN:")
        for ioc_type, threat_counts in analysis_results['threat_levels'].items():
            if threat_counts:
                report.append(f"  {ioc_type.upper()}:")
                for threat_level, count in threat_counts.items():
                    report.append(f"    - {threat_level}: {count}")
        
        # Recommendations
        report.append("\n💡 RECOMMENDATIONS:")
        for i, recommendation in enumerate(analysis_results['recommendations'], 1):
            report.append(f"  {i}. {recommendation}")
        
        if not analysis_results['recommendations']:
            report.append("  No immediate threats detected. Continue monitoring.")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)
    
    def export_to_csv(self, enriched_data, filename="threat_intelligence_export.csv"):
        """Export enriched data to CSV for further analysis"""
        rows = []
        
        for ioc_type, ioc_list in enriched_data.items():
            for ioc_data in ioc_list:
                rows.append({
                    'IOC_Type': ioc_type,
                    'IOC_Value': ioc_data['value'],
                    'Threat_Level': ioc_data['threat_level'],
                    'MISP_Match': 'Yes' if ioc_data['misp_data'] else 'No',
                    'Error': ioc_data.get('error', '')
                })
        
        df = pd.DataFrame(rows)
        df.to_csv(filename, index=False)
        print(f"Data exported to {filename}")
        return df

def main():
    # Sample intelligence feed for analysis
    sample_feed = """
    Security Alert: Ransomware Campaign Detected
    
    Multiple organizations report infections from ransomware family "CryptoLocker2024"
    
    Command and Control servers:
    - 198.51.100.42
    - 203.0.113.15
    - malware-c2.example.com
    - backup-c2.badsite.net
    
    Malware samples:
    MD5: d41d8cd98f00b204e9800998ecf8427e
    SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    
    Phishing campaign using:
    - sender@phishing-domain.com
    - http://phishing-domain.com/login
    - http://fake-bank.malicious.net/secure
    
    Additional indicators:
    - Registry key: HKLM\\Software\\CryptoLocker2024
    - File path: C:\\temp\\malware.exe
    - Mutex: Global\\CryptoLocker2024_Mutex
    """
    
    analyzer = IntelligenceAnalyzer()
    
    # Process the intelligence feed
    print("Processing intelligence feed...")
    results = analyzer.enricher.process_intel_feed(sample_feed)
    
    # Analyze the results
    print("Analyzing threat patterns...")
    analysis = analyzer.analyze_threat_patterns(results['enriched_data'])
    
    # Generate and display report
    report = analyzer.generate_report(analysis)
    print(report)
    
    # Export to CSV
    df = analyzer.export_to_csv(results['enriched_data'])
    print(f"\nProcessed {len(df)} IOCs total")
    
    # Display summary statistics
    print("\n📈 SUMMARY STATISTICS:")
    print(df['IOC_Type'].value_counts().to_string())

if __name__ == "__main__":
    main()
