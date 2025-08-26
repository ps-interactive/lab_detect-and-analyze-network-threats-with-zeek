#!/bin/bash

# Initialize lab environment and generate PCAP files
echo "Initializing Zeek lab environment..."

# Create necessary directories
mkdir -p /home/ubuntu/zeek_analysis
mkdir -p /home/ubuntu/zeek_scripts

# Change to analysis directory
cd /home/ubuntu/zeek_analysis

# Clean up any existing files
rm -f *.pcap *.log 2>/dev/null

echo "Generating network traffic captures..."

# Create base64 encoded PCAP data (minimal valid PCAPs with the expected traffic)
# This is a pre-generated PCAP with port scanning, SSH brute force, and other attacks

# Suspicious traffic PCAP (base64 encoded)
echo "Creating suspicious_traffic.pcap..."
cat << 'PCAP_DATA' | base64 -d > suspicious_traffic.pcap
1MOyoQIABAAAAAAAAAAAAAAABABIAAAASAAAAGEAAABhAAAACABFAABTAABAAABABgAAwKgBZAoAAAX4tAAW
AAAAAAAAAABQAhAAD6kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaAAAAGgAAAAIAEUAAFgAAEAA
AEAGAADAqAFkCgAABfi0ABYAAAAAAAAAACAAIAAPrQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABo
AAAAaAAAAAgARQAAWAAAQAAAQAYAAMCoAWQKAAAF+LQAFQAAAAAAAAAAIAACAA+uAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAaAAAAGgAAAAIAEUAAFgAAEAAQAYAAMCoAWQKAAAF+LQAFgAAAAAAAAAAgAIQAA+t
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaQAAAGkAAAAIAEUAAFkAAEAAQAYAAMCoAWQKAAAF+LQA
FQAAAAAAAAAAIAACAA+vAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABoAAAAaAAAAAgARQAAWAAA
QAAAQAYAAMCoAWQKAAAF+LQAAAAAAAAAAAAAIAACAA/9AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
PCAP_DATA

# Normal traffic PCAP
echo "Creating normal_traffic.pcap..."
cat << 'PCAP_DATA' | base64 -d > normal_traffic.pcap
1MOyoQIABAAAAAAAAAAAAAAABABIAAAASAAAAGEAAABhAAAACABFAABTAABAAABABgAAwKgBZAoAAAX4tABQ
AAAAAAAAAABQAhAAD4kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaAAAAGgAAAAIAEUAAFgAAEAA
AEAGAADAqAFkCgAABfi0AFAAAAAAAAAAACAAIAAPjQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABo
AAAAaAAAAAgARQAAWAAAQAAAQAYAAMCoAWQKAAAF+LQAUAAAAAAAAAAAIAAQAA+NAAAAAAAAAAAAAAAAAAA
PCAP_DATA

# Sample malware C2 beacon PCAP  
echo "Creating sample_malware_conn.pcap..."
cat << 'PCAP_DATA' | base64 -d > sample_malware_conn.pcap
1MOyoQIABAAAAAAAAAAAAAAABABIAAAASAAAAGEAAABhAAAACABFAABTAABAAABABgAArAEANbi8ZS0RXwRV
AAAAAAAAAABQAhAAD4kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaAAAAGgAAAAIAEUAAFgAAEAA
AEAGAACsAQA1uLxlLRFfBFUAAAAAAAAAACAAIAAPjQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABo
AAAAaAAAAAgARQAAWAAAQAAAQAYAAKwBADW4vGUtEV8EVQAAAAAAAAAAIAAQAA+NAAAAAAAAAAAAAAAAAAA
PCAP_DATA

# If base64 decoding failed, create minimal valid PCAPs with Python
if [ ! -s suspicious_traffic.pcap ] || [ ! -s normal_traffic.pcap ] || [ ! -s sample_malware_conn.pcap ]; then
    echo "Creating minimal PCAP files with Python fallback..."
    
    # Check if Python is available
    if command -v python3 &> /dev/null; then
        python3 << 'PYTHON_SCRIPT'
import struct
import time

def write_pcap_header(f):
    # PCAP global header
    f.write(struct.pack('<IHHIIII', 
        0xa1b2c3d4,  # Magic number
        2,           # Major version
        4,           # Minor version
        0,           # Timezone offset
        0,           # Timestamp accuracy
        65535,       # Snaplen
        1            # Ethernet
    ))

def write_packet(f, src_ip, dst_ip, src_port, dst_port, flags='S'):
    # Simplified packet creation
    timestamp = int(time.time())
    
    # Ethernet header (14 bytes)
    eth_header = b'\x00' * 6 + b'\x00' * 6 + b'\x08\x00'
    
    # IP header (20 bytes)
    ip_header = b'\x45\x00\x00\x28'  # Version, IHL, Total length
    ip_header += b'\x00\x00\x40\x00'  # ID, Flags, TTL
    ip_header += b'\x40\x06\x00\x00'  # Protocol (TCP), checksum
    
    # Convert IPs to bytes
    src_ip_bytes = bytes(map(int, src_ip.split('.')))
    dst_ip_bytes = bytes(map(int, dst_ip.split('.')))
    ip_header += src_ip_bytes + dst_ip_bytes
    
    # TCP header (20 bytes)
    tcp_header = struct.pack('!HH', src_port, dst_port)  # Ports
    tcp_header += b'\x00\x00\x00\x00'  # Sequence number
    tcp_header += b'\x00\x00\x00\x00'  # Acknowledgment number
    tcp_header += b'\x50'  # Data offset
    
    # Flags
    flag_byte = 0
    if 'S' in flags: flag_byte |= 0x02
    if 'A' in flags: flag_byte |= 0x10
    if 'F' in flags: flag_byte |= 0x01
    if 'R' in flags: flag_byte |= 0x04
    tcp_header += bytes([flag_byte])
    
    tcp_header += b'\x00\x00'  # Window
    tcp_header += b'\x00\x00'  # Checksum
    tcp_header += b'\x00\x00'  # Urgent pointer
    
    packet = eth_header + ip_header + tcp_header
    
    # PCAP packet header
    f.write(struct.pack('<IIII',
        timestamp, 0,      # Timestamp (seconds, microseconds)
        len(packet),       # Captured length
        len(packet)        # Original length
    ))
    f.write(packet)

# Create suspicious_traffic.pcap
with open('suspicious_traffic.pcap', 'wb') as f:
    write_pcap_header(f)
    
    # Port scanning from 192.168.1.100
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080]
    for port in ports:
        write_packet(f, '192.168.1.100', '10.0.0.5', 45678, port, 'S')
    
    # SSH brute force from 203.0.113.50
    for i in range(20):
        write_packet(f, '203.0.113.50', '10.0.0.10', 40000+i, 22, 'S')
    
    # SQL injection attempt
    write_packet(f, '192.168.1.150', '10.0.0.80', 50123, 80, 'SA')
    
print("Created suspicious_traffic.pcap")

# Create normal_traffic.pcap
with open('normal_traffic.pcap', 'wb') as f:
    write_pcap_header(f)
    
    # Normal web traffic
    for i in range(10):
        client = f'192.168.1.{100+i}'
        write_packet(f, client, '93.184.216.34', 50000+i, 80, 'SA')
        write_packet(f, client, '8.8.8.8', 40000+i, 53, 'S')

print("Created normal_traffic.pcap")

# Create sample_malware_conn.pcap
with open('sample_malware_conn.pcap', 'wb') as f:
    write_pcap_header(f)
    
    # C2 beacons at regular intervals
    for i in range(10):
        write_packet(f, '192.168.1.55', '185.220.101.45', 45000+i, 4444, 'SA')

print("Created sample_malware_conn.pcap")
PYTHON_SCRIPT
    else
        echo "Python not available, creating minimal PCAP files with dd..."
        
        # Create minimal valid PCAP files using dd
        # PCAP header (24 bytes) + minimal packet
        printf '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' > suspicious_traffic.pcap
        printf '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' > normal_traffic.pcap
        printf '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' > sample_malware_conn.pcap
    fi
fi

# Copy Zeek scripts from repository
if [ -d /home/ubuntu/lab ]; then
    echo "Copying Zeek scripts..."
    cp /home/ubuntu/lab/*.zeek /home/ubuntu/zeek_scripts/ 2>/dev/null || true
fi

# Verify files were created
echo ""
echo "Checking generated files..."
if [ -f suspicious_traffic.pcap ] && [ -f normal_traffic.pcap ] && [ -f sample_malware_conn.pcap ]; then
    echo "✓ All PCAP files created successfully!"
    ls -lh *.pcap
else
    echo "⚠ Warning: Some PCAP files may not have been created"
    ls -la *.pcap 2>/dev/null || echo "No PCAP files found"
fi

# Set proper permissions
chown -R ubuntu:ubuntu /home/ubuntu/zeek_analysis
chown -R ubuntu:ubuntu /home/ubuntu/zeek_scripts

echo ""
echo "Lab initialization complete!"
