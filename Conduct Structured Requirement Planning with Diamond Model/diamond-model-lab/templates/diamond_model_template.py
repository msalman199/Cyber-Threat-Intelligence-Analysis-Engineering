#!/usr/bin/env python3
"""
Diamond Model Framework for Threat Intelligence Analysis
"""

class DiamondModel:
    def __init__(self, incident_name):
        self.incident_name = incident_name
        self.adversary = {}
        self.capability = {}
        self.infrastructure = {}
        self.victim = {}
        self.meta_features = {}
        
    def set_adversary(self, **kwargs):
        self.adversary.update(kwargs)
        
    def set_capability(self, **kwargs):
        self.capability.update(kwargs)
        
    def set_infrastructure(self, **kwargs):
        self.infrastructure.update(kwargs)
        
    def set_victim(self, **kwargs):
        self.victim.update(kwargs)
        
    def set_meta_features(self, **kwargs):
        self.meta_features.update(kwargs)
        
    def generate_report(self):
        report = f"""
DIAMOND MODEL ANALYSIS: {self.incident_name}
{'='*50}

ADVERSARY:
{self._format_dict(self.adversary)}

CAPABILITY:
{self._format_dict(self.capability)}

INFRASTRUCTURE:
{self._format_dict(self.infrastructure)}

VICTIM:
{self._format_dict(self.victim)}

META-FEATURES:
{self._format_dict(self.meta_features)}
        """
        return report
        
    def _format_dict(self, data):
        if not data:
            return "  [No data available]"
        return '\n'.join([f"  {k}: {v}" for k, v in data.items()])
        
    def identify_gaps(self):
        gaps = []
        elements = {
            'Adversary': self.adversary,
            'Capability': self.capability,
            'Infrastructure': self.infrastructure,
            'Victim': self.victim
        }
        
        for element, data in elements.items():
            if not data:
                gaps.append(f"{element}: Complete data missing")
            else:
                # Check for common required fields
                required_fields = self._get_required_fields(element)
                missing = [field for field in required_fields if field not in data]
                if missing:
                    gaps.append(f"{element}: Missing {', '.join(missing)}")
        
        return gaps
        
    def _get_required_fields(self, element):
        field_map = {
            'Adversary': ['identity', 'motivation', 'sophistication'],
            'Capability': ['attack_vector', 'tools', 'techniques'],
            'Infrastructure': ['ip_addresses', 'domains', 'hosting'],
            'Victim': ['industry', 'geography', 'size']
        }
        return field_map.get(element, [])
