#!/bin/bash
# Test script to verify Zeek log analysis commands work

cd /home/ubuntu/zeek_analysis

echo "Testing Zeek log analysis commands..."
echo "======================================"
echo

# Check if conn.log exists
if [ ! -f conn.log ]; then
    echo "ERROR: conn.log not found. Run 'zeek -r suspicious_traffic.pcap' first"
    exit 1
fi

echo "1. Checking conn.log structure:"
echo "--------------------------------"
head -n 1 conn.log | grep "^#separator"
head -n 2 conn.log | grep "^#fields" | tr '\t' '\n' | head -10
echo

echo "2. Total connections (excluding headers):"
echo "------------------------------------------"
TOTAL=$(grep -v "^#" conn.log | wc -l)
echo "Total connection records: $TOTAL"
echo

echo "3. Connection states distribution:"
echo "-----------------------------------"
echo "Using awk to extract conn_state field (column 12):"
grep -v "^#" conn.log | awk -F'\t' '{print $12}' | sort | uniq -c | sort -rn | head -5
echo

echo "4. Top source IPs and ports:"
echo "-----------------------------"
echo "Using awk to extract source IP (col 3) and dest port (col 6):"
grep -v "^#" conn.log | awk -F'\t' '{print $3, $6}' | sort | uniq -c | sort -rn | head -5
echo

echo "5. SSH connections (port 22):"
echo "------------------------------"
echo "Connections to port 22:"
grep -v "^#" conn.log | awk -F'\t' '{if ($6 == 22) print $1, $3, $6}' | head -5
echo

echo "6. Services detected:"
echo "----------------------"
echo "Service field distribution (column 7):"
grep -v "^#" conn.log | awk -F'\t' '{print $7}' | sort | uniq -c | sort -rn | head -5
echo

echo "7. Connection history patterns:"
echo "--------------------------------"
echo "Showing history field (column 16) for scanning patterns:"
grep -v "^#" conn.log | awk -F'\t' '{if ($16 ~ /^S$|^Sr$|^OTH/) print $3, $5, $6, $16}' | head -5
echo

echo "Test complete!"
