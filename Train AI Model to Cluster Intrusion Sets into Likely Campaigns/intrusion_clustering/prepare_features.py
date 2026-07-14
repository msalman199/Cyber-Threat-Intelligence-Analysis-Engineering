import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer

def prepare_clustering_features(df):
    """Prepare features for clustering analysis"""
    
    # Create a copy for processing
    data = df.copy()
    
    # Convert timestamp to numerical features
    data['timestamp'] = pd.to_datetime(data['timestamp'])
    data['hour_of_day'] = data['timestamp'].dt.hour
    data['day_of_week'] = data['timestamp'].dt.dayofweek
    
    # Encode categorical variables
    le_country = LabelEncoder()
    le_attack_type = LabelEncoder()
    
    data['source_country_encoded'] = le_country.fit_transform(data['source_country'])
    data['attack_type_encoded'] = le_attack_type.fit_transform(data['attack_type'])
    
    # Select numerical features for clustering
    feature_columns = [
        'target_port', 'payload_size', 'duration_minutes', 
        'packets_sent', 'bytes_transferred', 'success_rate',
        'hour_of_day', 'day_of_week', 'source_country_encoded', 
        'attack_type_encoded'
    ]
    
    features = data[feature_columns].copy()
    
    # Handle any missing values
    features = features.fillna(features.mean())
    
    # Scale features
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(features)
    
    return features_scaled, feature_columns, data, scaler, le_country, le_attack_type

# Load and prepare data
df = pd.read_csv('intrusion_data.csv')
features_scaled, feature_names, processed_data, scaler, le_country, le_attack_type = prepare_clustering_features(df)

print(f"Prepared {features_scaled.shape[0]} samples with {features_scaled.shape[1]} features")
print(f"Feature names: {feature_names}")

# Save processed data
np.save('features_scaled.npy', features_scaled)
processed_data.to_csv('processed_data.csv', index=False)

print("Feature preparation complete!")
