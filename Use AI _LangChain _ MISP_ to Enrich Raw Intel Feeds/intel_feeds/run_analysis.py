#!/usr/bin/env python3

import os
import glob
from intel_enricher import IntelligenceEnricher
from intel_analyzer import IntelligenceAnalyzer

def process_multiple_feeds():
    """Process multiple intelligence feeds and generate comprehensive analysis"""
    
    enricher = IntelligenceEnricher()
    analyzer = IntelligenceAnalyzer()
    
    # Process all feed files
    feed_files = glob.glob("intel_feeds/*.txt")
    all_results = []
    
    print("🔍 Processing Intelligence Feeds...")
    print("=" * 50)
    
    for feed_file in feed_files:
        print(f"\nProcessing: {feed_file}")
        
        with open(feed_file, 'r') as f:
            feed_content = f.read()
        
        # Process the feed
        results = enricher.process_intel_feed(feed_content)
        all_results.append({
            'source': feed_file,
            'results': results
        })
        
        # Quick summary
        total_iocs = sum(len(v) for v in results['extracted_iocs'].values())
        print(f"  ✓ Extracted {total_iocs} IOCs")
        print(f"  ✓ Created MISP event: {results['misp_event_id']}")
    
    # Combine all results for comprehensive analysis
    combined_enriched_data = {
        'ips': [],
        'domains': [],
        'urls': [],
        'hashes': [],
        'emails': []
    }
    
    for result_set in all_results:
        for ioc_type in combined_enriched_data.keys():
            combined_enriched_data[ioc_type].extend(
                result_set['results']['enriched_data'].get(ioc_type, [])
            )
    
    # Generate comprehensive analysis
    print("\n🔬 COMPREHENSIVE THREAT ANALYSIS")
    print("=" * 50)
    
    analysis = analyzer.analyze_threat_patterns(combined_enriched_data)
    report = analyzer.generate_report(analysis)
    print(report)
    
    # Export comprehensive dataset
    df = analyzer.export_to_csv(combined_enriched_data, "comprehensive_threat_intel.csv")
    
    return all_results, analysis

if __name__ == "__main__":
    results, analysis = process_multiple_feeds()
