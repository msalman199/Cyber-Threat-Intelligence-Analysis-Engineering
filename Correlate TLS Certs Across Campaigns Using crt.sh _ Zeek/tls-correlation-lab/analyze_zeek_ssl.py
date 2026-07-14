#!/usr/bin/env python3
import pandas as pd
import json
from collections import defaultdict
import os

def load_zeek_ssl_log():
    """Load and parse Zeek SSL log"""
    ssl_file = 'zeek-logs/ssl.log'
    
    if not os.path.exists(ssl_file):
        print("SSL log not found. Generating sample data...")
        return create_sample_ssl_data()
    
    try:
        # Read Zeek SSL log (tab-separated)
        df = pd.read_csv(ssl_file, sep='\t', comment='#', 
                        names=['ts', 'uid', 'id.orig_h', 'id.orig_p', 
                              'id.resp_h', 'id.resp_p', 'version', 'cipher',
                              'curve', 'server_name', 'resumed', 'last_alert',
                              'next_protocol', 'established', 'cert_chain_fuids',
                              'client_cert_chain_fuids', 'subject', 'issuer',
                              'client_subject', 'client_issuer', 'validation_status'])
        return df
    except Exception as e:
        print(f"Error reading SSL log: {e}")
        return create_sample_ssl_data()

def create_sample_ssl_data():
    """Create sample SSL data for demonstration"""
    sample_data = [
        {
            'ts': '1640995200.0',
            'server_name': 'malware-c2.com',
            'subject': 'CN=malware-c2.com',
            'issuer': 'CN=Let\'s Encrypt Authority X3',
            'cert_chain_fuids': 'FabcDef123456',
            'validation_status': 'ok'
        },
        {
            'ts': '1640995300.0',
            'server_name': 'phishing-site.net',
            'subject': 'CN=phishing-site.net',
            'issuer': 'CN=Let\'s Encrypt Authority X3',
            'cert_chain_fuids': 'FghiJkl789012',
            'validation_status': 'ok'
        },
        {
            'ts': '1640995400.0',
            'server_name': 'apt-infrastructure.org',
            'subject': 'CN=apt-infrastructure.org',
            'issuer': 'CN=Let\'s Encrypt Authority X3',
            'cert_chain_fuids': 'FmnoPqr345678',
            'validation_status': 'ok'
        }
    ]
    
    return pd.DataFrame(sample_data)

def extract_cert_fingerprints(df):
    """Extract certificate fingerprints and metadata"""
    cert_info = []
    
    for _, row in df.iterrows():
        if pd.notna(row.get('cert_chain_fuids')):
            cert_info.append({
                'timestamp': row.get('ts'),
                'server_name': row.get('server_name'),
                'subject': row.get('subject'),
                'issuer': row.get('issuer'),
                'cert_fuid': row.get('cert_chain_fuids'),
                'validation_status': row.get('validation_status')
            })
    
    return cert_info

def correlate_with_crtsh_data(zeek_certs):
    """Correlate Zeek certificate data with crt.sh findings"""
    correlations = []
    
    # Load crt.sh data
    crtsh_data = []
    for filename in os.listdir('analysis'):
        if filename.endswith('_details.json'):
            with open(f'analysis/{filename}', 'r') as f:
                data = json.load(f)
                crtsh_data.extend(data)
    
    # Find correlations
    for zeek_cert in zeek_certs:
        zeek_server = zeek_cert.get('server_name', '')
        zeek_issuer = zeek_cert.get('issuer', '')
        
        for crtsh_cert in crtsh_data:
            crtsh_cn = crtsh_cert.get('common_name', '')
            crtsh_issuer = crtsh_cert.get('issuer_name', '')
            
            if zeek_server in crtsh_cn or crtsh_issuer in zeek_issuer:
                correlations.append({
                    'zeek_server': zeek_server,
                    'zeek_issuer': zeek_issuer,
                    'crtsh_domain': crtsh_cert.get('domain_searched'),
                    'crtsh_issuer': crtsh_issuer,
                    'correlation_type': 'issuer_match' if crtsh_issuer in zeek_issuer else 'domain_match'
                })
    
    return correlations

if __name__ == "__main__":
    print("Loading Zeek SSL logs...")
    ssl_df = load_zeek_ssl_log()
    
    print(f"Found {len(ssl_df)} SSL connections")
    
    cert_info = extract_cert_fingerprints(ssl_df)
    print(f"Extracted {len(cert_info)} certificate records")
    
    # Save certificate info
    with open('analysis/zeek_cert_info.json', 'w') as f:
        json.dump(cert_info, f, indent=2)
    
    print("\n=== Zeek Certificate Analysis ===")
    for cert in cert_info:
        print(f"Server: {cert['server_name']}")
        print(f"  Subject: {cert['subject']}")
        print(f"  Issuer: {cert['issuer']}")
        print(f"  FUID: {cert['cert_fuid']}")
        print()
    
    print("=== Correlating with crt.sh data ===")
    correlations = correlate_with_crtsh_data(cert_info)
    
    if correlations:
        for corr in correlations:
            print(f"Correlation found:")
            print(f"  Zeek: {corr['zeek_server']} ({corr['zeek_issuer']})")
            print(f"  crt.sh: {corr['crtsh_domain']} ({corr['crtsh_issuer']})")
            print(f"  Type: {corr['correlation_type']}")
            print()
    else:
        print("No direct correlations found in sample data")
