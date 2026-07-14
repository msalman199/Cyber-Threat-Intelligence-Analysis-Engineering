#!/bin/bash
echo "=== ATTACK SURFACE ANALYSIS ===" > attack_surface.txt
echo "" >> attack_surface.txt

echo "Unique IP addresses identified:" >> attack_surface.txt
cut -d',' -f2 domain_ip_mapping.csv | sort -u | wc -l >> attack_surface.txt
echo "" >> attack_surface.txt

echo "Unique domains identified:" >> attack_surface.txt
wc -l < amass_results.txt >> attack_surface.txt
echo "" >> attack_surface.txt

echo "Potential entry points (subdomains):" >> attack_surface.txt
grep -E "(admin|test|dev|staging|api|mail|ftp)" amass_results.txt | head -10 >> attack_surface.txt
echo "" >> attack_surface.txt
