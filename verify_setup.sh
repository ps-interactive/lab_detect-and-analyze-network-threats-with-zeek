#!/bin/bash
# Verify Zeek lab setup

echo "Verifying Zeek Lab Environment Setup..."
echo "======================================="

# Check if Zeek is installed
if command -v zeek &> /dev/null; then
    echo "✓ Zeek is installed: $(zeek --version 2>&1 | head -1)"
elif command -v bro &> /dev/null; then
    echo "✓ Bro (older Zeek) is installed: $(bro --version 2>&1 | head -1)"
else
    echo "✗ Zeek is not installed"
    exit 1
fi

# Check if zeek-cut is available
if command -v zeek-cut &> /dev/null; then
    echo "✓ zeek-cut is available"
else
    echo "✗ zeek-cut is not found"
fi

# Check required directories
if [ -d "/home/ubuntu/zeek_analysis" ]; then
    echo "✓ Analysis directory exists"
else
    echo "✗ Analysis directory missing"
fi

if [ -d "/home/ubuntu/zeek_scripts" ]; then
    echo "✓ Scripts directory exists"
else
    echo "✗ Scripts directory missing"
fi

# Check for PCAP files
echo ""
echo "Checking PCAP files..."
cd /home/ubuntu/zeek_analysis

for pcap in suspicious_traffic.pcap normal_traffic.pcap sample_malware_conn.pcap; do
    if [ -f "$pcap" ]; then
        SIZE=$(stat -c%s "$pcap" 2>/dev/null || echo "0")
        if [ "$SIZE" -gt "1000" ]; then
            echo "  ✓ $pcap found (${SIZE} bytes)"
        else
            echo "  ✗ $pcap too small (${SIZE} bytes)"
        fi
    else
        echo "  ✗ $pcap missing"
    fi
done

# Check for pre-generated logs
echo ""
echo "Checking protocol logs..."
for log in http.log dns.log; do
    if [ -f "$log" ]; then
        LINES=$(wc -l < "$log" 2>/dev/null || echo "0")
        echo "  ✓ $log found ($LINES lines)"
    else
        echo "  ✗ $log missing"
    fi
done

# Check for Zeek scripts
echo ""
echo "Checking Zeek scripts..."
for script in detect_scans.zeek protocol_anomaly.zeek correlation_rules.zeek; do
    if [ -f "/home/ubuntu/zeek_scripts/$script" ]; then
        echo "  ✓ $script found"
    else
        echo "  ✗ $script missing"
    fi
done

# Process suspicious_traffic.pcap to verify Zeek works
echo ""
echo "Testing Zeek processing..."
if [ -f "suspicious_traffic.pcap" ]; then
    zeek -r suspicious_traffic.pcap 2>/dev/null
    if [ -f "conn.log" ]; then
        CONN_COUNT=$(zeek-cut < conn.log | wc -l 2>/dev/null || echo "0")
        echo "  ✓ Zeek processed PCAP successfully ($CONN_COUNT connections)"
        # Clean up test logs
        rm -f conn.log packet_filter.log reporter.log weird.log 2>/dev/null
    else
        echo "  ✗ Zeek failed to process PCAP"
    fi
else
    echo "  ✗ Cannot test - suspicious_traffic.pcap missing"
fi

# Final status
echo ""
echo "======================================="

# Check if all critical components are ready
READY=true
[ ! -f "/home/ubuntu/zeek_analysis/suspicious_traffic.pcap" ] && READY=false
[ ! -f "/home/ubuntu/zeek_analysis/http.log" ] && READY=false
[ ! -f "/home/ubuntu/zeek_analysis/dns.log" ] && READY=false
[ ! -d "/home/ubuntu/zeek_scripts" ] && READY=false

if [ "$READY" = true ]; then
    echo "✓ Lab environment is ready!"
else
    echo "✗ Lab environment has issues - check errors above"
fi

echo "======================================="
