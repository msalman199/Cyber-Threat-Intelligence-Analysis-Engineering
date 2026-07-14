import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

def generate_intrusion_data():
    """Generate synthetic intrusion data representing different attack campaigns"""
    
    # Define attack campaign characteristics
    campaigns = {
        'APT_Campaign_A': {
            'source_countries': ['CN', 'RU'],
            'target_ports': [22, 80, 443, 3389],
            'attack_types': ['brute_force', 'web_exploit', 'lateral_movement'],
            'payload_sizes': (1000, 5000),
            'duration_hours': (2, 8)
        },
        'Ransomware_Campaign_B': {
            'source_countries': ['RU', 'KP'],
            'target_ports': [445, 135, 139],
            'attack_types': ['smb_exploit', 'file_encryption', 'credential_theft'],
            'payload_sizes': (5000, 20000),
            'duration_hours': (1, 4)
        },
        'Botnet_Campaign_C': {
            'source_countries': ['US', 'DE', 'BR'],
            'target_ports': [80, 8080, 53],
            'attack_types': ['ddos', 'spam', 'crypto_mining'],
            'payload_sizes': (500, 2000),
            'duration_hours': (12, 48)
        },
        'Phishing_Campaign_D': {
            'source_countries': ['NG', 'IN', 'PH'],
            'target_ports': [25, 587, 993],
            'attack_types': ['email_spoofing', 'credential_harvest', 'social_engineering'],
            'payload_sizes': (200, 1000),
            'duration_hours': (0.5, 2)
        }
    }
    
    intrusions = []
    base_time = datetime.now() - timedelta(days=30)
    
    for campaign_name, characteristics in campaigns.items():
        # Generate 50-100 intrusions per campaign
        num_intrusions = random.randint(50, 100)
        
        for i in range(num_intrusions):
            intrusion = {
                'intrusion_id': f"{campaign_name}_{i:03d}",
                'timestamp': base_time + timedelta(
                    hours=random.uniform(0, 720),  # 30 days
                    minutes=random.randint(0, 59)
                ),
                'source_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'source_country': random.choice(characteristics['source_countries']),
                'target_port': random.choice(characteristics['target_ports']),
                'attack_type': random.choice(characteristics['attack_types']),
                'payload_size': random.randint(*characteristics['payload_sizes']),
                'duration_minutes': random.uniform(*[h*60 for h in characteristics['duration_hours']]),
                'packets_sent': random.randint(10, 1000),
                'bytes_transferred': random.randint(1000, 100000),
                'success_rate': random.uniform(0.1, 0.9),
                'true_campaign': campaign_name  # Ground truth for evaluation
            }
            intrusions.append(intrusion)
    
    # Add some noise/outliers
    for i in range(20):
        noise_intrusion = {
            'intrusion_id': f"NOISE_{i:03d}",
            'timestamp': base_time + timedelta(hours=random.uniform(0, 720)),
            'source_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'source_country': random.choice(['XX', 'YY', 'ZZ']),
            'target_port': random.randint(1, 65535),
            'attack_type': 'unknown',
            'payload_size': random.randint(1, 50000),
            'duration_minutes': random.uniform(1, 1440),
            'packets_sent': random.randint(1, 2000),
            'bytes_transferred': random.randint(100, 200000),
            'success_rate': random.uniform(0, 1),
            'true_campaign': 'NOISE'
        }
        intrusions.append(noise_intrusion)
    
    return pd.DataFrame(intrusions)

# Generate and save dataset
print("Generating synthetic intrusion dataset...")
df = generate_intrusion_data()
df.to_csv('intrusion_data.csv', index=False)
print(f"Generated {len(df)} intrusion records")
print(f"Campaigns: {df['true_campaign'].value_counts().to_dict()}")
