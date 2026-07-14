#!/usr/bin/env python3
import json
import os
from datetime import datetime

def generate_final_report():
    """Generate comprehensive correlation report"""
    
    report_data = {}
    
    # Load all analysis results
    analysis_files = {
        'attribution_report.json': 'infrastructure_attribution',
        'timeline_summary.json': 'timeline_analysis',
        'zeek_cert_info.json': 'network_analysis'
    }
    
    for filename, key in analysis_files.items():
        filepath = f'analysis/{filename}'
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                report_data[key] = json.load(f)
    
    # Generate executive summary
    executive_summary = generate_executive_summary(report_data)
    
    # Create final report structure
    final_report = {
        'report_metadata': {
            'generated_at': datetime.now().isoformat(),
            'lab_name': 'TLS Certificate Correlation Analysis',
            'analysis_scope': 'Multi-campaign infrastructure attribution'
        },
        'executive_summary': executive_summary,
        'detailed_findings': report_data,
        'recommendations': generate_recommendations(report_data),
        'iocs': extract_iocs(report_data)
    }
    
    # Save final report
    with open('analysis/FINAL_CORRELATION_REPORT.json', 'w') as f:
        json.dump(final_report, f, indent=2)
    
    # Generate human-readable report
    generate_readable_report(final_report)
    
    return final_report

def generate_executive_summary(data):
    """Generate executive summary of findings"""
    summary = {
        'key_findings': [],
        'infrastructure_overlap': 0,
        'campaign_correlation_confidence': 'medium',
        'threat_actor_attribution': 'possible'
    }
    
    if 'infrastructure_attribution' in data:
        infra_data = data['infrastructure_attribution']
        
        if 'high_confidence_links' in infra_data:
            high_conf_links = len(infra_data['high_confidence_links'])
            if high_conf_links > 0:
                summary['key_findings'].append(f"Found {high_conf_links} high-confidence infrastructure links")
                summary['campaign_correlation_confidence'] = 'high'
        
        if 'summary' in infra_data:
            total_certs = infra_data['summary'].get('total_certificates', 0)
            unique_issuers = infra_data['summary'].get('unique_issuers', 0)
            
            summary['key_findings'].append(f"Analyzed {total_certs} certificates from {unique_issuers} issuers")
    
    if 'timeline_analysis' in data:
        timeline_data = data['timeline_analysis']
        timespan = timeline_data.get('total_timespan_days', 0)
        
        if timespan > 0:
            summary['key_findings'].append(f"Campaign activity spans {timespan} days")
    
    return summary

def generate_recommendations(data):
    """Generate security recommendations based on findings"""
    recommendations = [
        "Monitor certificate transparency logs for similar infrastructure patterns",
        "Implement certificate pinning for critical applications",
        "Set up alerts for certificates issued by suspicious CAs",
        "Correlate certificate data with other threat intelligence sources"
    ]
    
    if 'infrastructure_attribution' in data:
        infra_data = data['infrastructure_attribution']
        if infra_data.get('high_confidence_links'):
            recommendations.append("Block identified malicious certificate authorities")
            recommendations.append("Implement DNS sinkholing for correlated domains")
    
    return recommendations

def extract_iocs(data):
    """Extract Indicators of Compromise from analysis"""
    iocs = {
        'domains': [],
        'certificate_issuers': [],
        'certificate_serials': []
    }
    
    if 'infrastructure_attribution' in data:
        infra_data = data['infrastructure_attribution']
        
        for link in infra_data.get('high_confidence_links', []):
            iocs['domains'].extend(link.get('linked_domains', []))
            iocs['certificate_issuers'].append(link.get('issuer', ''))
    
    # Remove duplicates
    iocs['domains'] = list(set(iocs['domains']))
    iocs['certificate_issuers'] = list(set(filter(None, iocs['certificate_issuers'])))
    
    return iocs

def generate_readable_report(report):
    """Generate human-readable report"""
    
    readable_report = f"""
# TLS Certificate Correlation Analysis Report

**Generated:** {report['report_metadata']['generated_at']}

## Executive Summary

{chr(10).join(f"• {finding}" for finding in report['executive_summary']['key_findings'])}

**Campaign Correlation Confidence:** {report['executive_summary']['campaign_correlation_confidence'].upper()}

## Key Indicators of Compromise (IOCs)

### Malicious Domains
{chr(10).join(f"• {domain}" for domain in report['iocs']['domains'])}

### Suspicious Certificate Issuers
{chr(10).join(f"• {issuer}" for issuer in report['iocs']['certificate_issuers'])}

## Security Recommendations

{chr(10).join(f"{i+1}. {rec}" for i, rec in enumerate(report['recommendations']))}

## Analysis Artifacts Generated

• Infrastructure correlation map: analysis/infrastructure_map.png
• Campaign timeline: analysis/campaign_timeline.png
• Detailed JSON reports in analysis/ directory

---
*This report was generated using open-source tools: crt.sh API, Zeek network monitor, and Python analysis scripts.*
"""
    
    with open('analysis/CORRELATION_REPORT.md', 'w') as f:
        f.write(readable_report)
    
    print("Human-readable report saved to analysis/CORRELATION_REPORT.md")

if __name__ == "__main__":
    print("Generating final correlation report...")
    report = generate_final_report()
    
    print("\n" + "="*60)
    print("FINAL CORRELATION ANALYSIS COMPLETE")
    print("="*60)
    
    print(f"\nExecutive Summary:")
    for finding in report['executive_summary']['key_findings']:
        print(f"  • {finding}")
    
    print(f"\nCorrelation Confidence: {report['executive_summary']['campaign_correlation_confidence'].upper()}")
    
    print(f"\nIOCs Identified:")
    print(f"  • Domains: {len(report['iocs']['domains'])}")
    print(f"  • Certificate Issuers: {len(report['iocs']['certificate_issuers'])}")
    
    print(f"\nReports Generated:")
    print(f"  • analysis/FINAL_CORRELATION_REPORT.json")
    print(f"  • analysis/CORRELATION_REPORT.md")
    
    if os.path.exists('analysis/infrastructure_map.png'):
        print(f"  • analysis/infrastructure_map.png")
    if os.path.exists('analysis/campaign_timeline.png'):
        print(f"  • analysis/campaign_timeline.png")
