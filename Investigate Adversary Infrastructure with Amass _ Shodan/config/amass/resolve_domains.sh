#!/bin/bash
echo "Resolving domains to IP addresses..."
while read domain; do
    ip=$(dig +short $domain | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    if [ ! -z "$ip" ]; then
        echo "$domain,$ip"
    fi
