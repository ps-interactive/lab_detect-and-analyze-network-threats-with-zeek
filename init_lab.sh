#!/bin/bash

# Lab initialization script
echo "Initializing Zeek Network Threat Analysis Lab..."

# Create necessary directories
mkdir -p /home/ubuntu/zeek_analysis
mkdir -p /home/ubuntu/zeek_scripts

# Copy Zeek scripts
cp /home/ubuntu/lab/*.zeek /home/ubuntu/zeek_scripts/ 2>/dev/null || true

# Generate traffic patterns using Python
cd /home/ubuntu/zeek_analysis

# Check if Python3 and scapy are available
if command -v python3 &> /dev/null && python3 -c "import scapy" 2>/dev/null; then
    echo "Generating network traffic patterns..."
    python3 /home/ubuntu/lab/generate_traffic.py
else
    echo "Python environment not ready, creating fallback PCAPs..."
    # Create minimal valid PCAP files as fallback
    for pcap in suspicious_traffic.pcap normal_traffic.pcap sample_malware_conn.pcap; do
        if [ ! -f "$pcap" ]; then
            # PCAP magic header for a valid empty PCAP file
            echo -ne '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' > "$pcap"
        fi
    done
fi

# Verify files exist
for file in suspicious_traffic.pcap normal_traffic.pcap sample_malware_conn.pcap; do
    if [ -f "$file" ]; then
        echo "✓ $file created successfully"
    else
        echo "✗ Failed to create $file"
    fi
done

echo "Lab initialization complete!"
