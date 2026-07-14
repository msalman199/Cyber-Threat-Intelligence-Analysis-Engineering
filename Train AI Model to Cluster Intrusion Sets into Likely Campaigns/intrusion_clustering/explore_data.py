import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load the dataset
df = pd.read_csv('intrusion_data.csv')

print("Dataset Overview:")
print(f"Shape: {df.shape}")
print(f"Columns: {list(df.columns)}")
print("\nFirst few records:")
print(df.head())

print("\nCampaign distribution:")
print(df['true_campaign'].value_counts())

print("\nAttack type distribution:")
print(df['attack_type'].value_counts())

print("\nSource country distribution:")
print(df['source_country'].value_counts())

# Create basic visualizations
plt.figure(figsize=(15, 10))

plt.subplot(2, 3, 1)
df['true_campaign'].value_counts().plot(kind='bar')
plt.title('True Campaign Distribution')
plt.xticks(rotation=45)

plt.subplot(2, 3, 2)
df['attack_type'].value_counts().plot(kind='bar')
plt.title('Attack Type Distribution')
plt.xticks(rotation=45)

plt.subplot(2, 3, 3)
df['source_country'].value_counts().plot(kind='bar')
plt.title('Source Country Distribution')

plt.subplot(2, 3, 4)
plt.scatter(df['payload_size'], df['duration_minutes'], alpha=0.6)
plt.xlabel('Payload Size')
plt.ylabel('Duration (minutes)')
plt.title('Payload Size vs Duration')

plt.subplot(2, 3, 5)
plt.scatter(df['packets_sent'], df['bytes_transferred'], alpha=0.6)
plt.xlabel('Packets Sent')
plt.ylabel('Bytes Transferred')
plt.title('Network Activity Pattern')

plt.subplot(2, 3, 6)
plt.hist(df['success_rate'], bins=20, alpha=0.7)
plt.xlabel('Success Rate')
plt.ylabel('Frequency')
plt.title('Attack Success Rate Distribution')

plt.tight_layout()
plt.savefig('data_exploration.png', dpi=300, bbox_inches='tight')
plt.show()

print("\nData exploration complete. Visualization saved as 'data_exploration.png'")
