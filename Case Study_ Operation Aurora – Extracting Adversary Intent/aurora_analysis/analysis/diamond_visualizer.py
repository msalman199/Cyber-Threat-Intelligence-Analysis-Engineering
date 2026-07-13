#!/usr/bin/env python3

def create_diamond_visualization():
    visualization = '''
OPERATION AURORA - DIAMOND MODEL VISUALIZATION
==============================================

                    ADVERSARY
                 ┌─────────────────┐
                 │   APT1/Comment  │
                 │      Crew       │
                 │                 │
                 │ • State-sponsored│
                 │ • Espionage     │
                 │ • Advanced      │
                 └─────────────────┘
                          │
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│INFRASTRUCTURE│    │ CAPABILITY  │    │   VICTIM    │
│             │    │             │    │             │
│• C2 Domains │    │• Hydraq     │    │• Google     │
│• Bulletproof│    │• Zero-day   │    │• Adobe      │
│  Hosting    │    │• Spear-     │    │• Yahoo      │
│• Typosquat  │    │  phishing   │    │• Tech Sector│
│  Domains    │    │• Lateral    │    │• US-based   │
│             │    │  Movement   │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
                    RELATIONSHIPS
                 ┌─────────────────┐
                 │ • Targeted      │
                 │ • Persistent    │
                 │ • Sophisticated │
                 │ • State-nexus   │
                 └─────────────────┘

KEY INSIGHTS:
============
1. State-sponsored adversary with clear espionage objectives
2. Sophisticated capability set including zero-day exploits
3. Targeted victim selection in technology and defense sectors
4. Professional infrastructure management and operational security
5. Long-term persistent access goals rather than quick financial gain
'''
    return visualization

if __name__ == "__main__":
    print(create_diamond_visualization())
    
    # Save visualization to file
    with open('../analysis/diamond_visualization.txt', 'w') as f:
        f.write(create_diamond_visualization())
    
    print("Visualization saved to: ../analysis/diamond_visualization.txt")
