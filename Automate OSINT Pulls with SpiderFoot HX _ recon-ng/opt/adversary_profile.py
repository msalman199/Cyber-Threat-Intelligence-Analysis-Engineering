#!/usr/bin/env python3
import json
import sys
from datetime import datetime

def generate_adversary_profile(correlation_file):
    """Generate adversary profile from correlated OSINT data"""
    
    try:
        with open(correlation_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("Correlation file not found. Run correlation script first.")
        return
    
    profile = {
        'target_analysis': {
            'assessment_date': datetime.now().isoformat(),
            'data_sources': ['SpiderFoot HX', 'recon-ng'],
            'confidence_level': 'Medium'
        },
        'infrastructure': {
            'ip_addresses': data.get('ip_addresses', []),
            'domains': data.get('domains', []),
            'subdomains': []
        },
        'attack_surface': {
            'exposed_services': [],
            'email_addresses': data.get('emails', []),
            'social_media_presence': len(data.get('social_profiles', []))
        },
        'risk_assessment': {
            'exposure_level': 'TBD',
            'recommendations': []
        }
    }
    
    # Analyze infrastructure
    ip_count = len(profile['infrastructure']['ip_addresses'])
    domain_count = len(profile['infrastructure']['domains'])
    
    if ip_count > 10:
        profile['risk_assessment']['exposure_level'] = 'High'
        profile['risk_assessment']['recommendations'].append(
            'Large IP address space detected - review for unnecessary exposure'
        )
    elif ip_count > 5:
        profile['risk_assessment']['exposure_level'] = 'Medium'
    else:
        profile['risk_assessment']['exposure_level'] = 'Low'
    
    # Analyze email exposure
    email_count = len(profile['attack_surface']['email_addresses'])
    if email_count > 5:
        profile['risk_assessment']['recommendations'].append(
            'Multiple email addresses exposed - potential for social engineering'
        )
    
    # Save profile
    profile_file = '/opt/adversary_profile.json'
    with open(profile_file, 'w') as f:
        json.dump(profile, f, indent=2)
    
    print("=== ADVERSARY PROFILE GENERATED ===")
    print(f"Target Infrastructure: {ip_count} IPs, {domain_count} domains")
    print(f"Email Exposure: {email_count} addresses")
    print(f"Social Media Presence: {profile['attack_surface']['social_media_presence']} profiles")
    print(f"Risk Level: {profile['risk_assessment']['exposure_level']}")
    print(f"Profile saved to: {profile_file}")
    
    return profile

if __name__ == "__main__":
    correlation_file = '/opt/correlated_findings.json'
    generate_adversary_profile(correlation_file)
