#!/usr/bin/env python3
import json
import requests
from collections import defaultdict

# Query Elasticsearch for attack data
response = requests.get('http://localhost:9200/attack-data/_search?size=1000')
data = response.json()

# Process data for ATT&CK Navigator
techniques = defaultdict(int)
for hit in data['hits']['hits']:
    source = hit['_source']
    technique_id = source.get('technique_id', '')
    if technique_id:
        techniques[technique_id] += 1

# Create ATT&CK Navigator layer
layer = {
    "name": "Campaign Analysis",
    "versions": {
        "attack": "14",
        "navigator": "4.9.1",
        "layer": "4.5"
    },
    "domain": "enterprise-attack",
    "description": "Heatmap showing technique frequency from campaign data",
    "techniques": []
}

# Add techniques with scores
for technique_id, count in techniques.items():
    layer["techniques"].append({
        "techniqueID": technique_id,
        "score": min(count * 20, 100),  # Scale score (max 100)
        "color": "",
        "comment": f"Observed {count} times",
        "enabled": True,
        "metadata": [],
        "links": [],
        "showSubtechniques": False
    })

# Save layer file
with open('campaign_layer.json', 'w') as f:
    json.dump(layer, f, indent=2)

print(f"Created ATT&CK layer with {len(techniques)} techniques")
print("Layer saved as campaign_layer.json")
