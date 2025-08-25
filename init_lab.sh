#!/bin/bash

# Initialize lab environment
echo "Initializing Zeek Network Threat Analysis Lab..."

# Ensure we're in the correct directory
cd /home/ubuntu/zeek_analysis 2>/dev/null || cd ~/zeek_analysis

# Check if PCAPs already exist
if [ -f "suspicious_traffic.pcap" ] && [ -f "normal_traffic.pcap" ] && [ -f "sample_malware_conn.pcap" ]; then
    echo "PCAP files already exist."
else
    echo "Generating PCAP files..."
    
    # Check if generation script exists in lab directory
    if [ -f "/home/ubuntu/lab/generate_pcaps.py" ]; then
        python3 /home/ubuntu/lab/generate_pcaps.py
        mv /tmp/*.pcap /home/ubuntu/zeek_analysis/ 2>/dev/null || true
    else
        echo "Warning: PCAP generation script not found, creating minimal PCAPs..."
        # Fallback: create minimal valid PCAP files
        echo -ne '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' > suspicious_traffic.pcap
        echo -ne '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' > normal_traffic.pcap
        echo -ne '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' > sample_malware_conn.pcap
    fi
fi

# Set proper permissions
chmod 644 *.pcap 2>/dev/null

echo "Lab initialization complete!"
echo "PCAP files available:"
ls -lh *.pcap 2>/dev/null || echo "No PCAP files found"
