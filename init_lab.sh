#!/bin/bash
# Initialize lab environment if setup didn't complete

echo "Initializing Zeek Lab Environment..."
echo "===================================="
echo

# Create required directories
echo "Creating directories..."
mkdir -p /home/ubuntu/zeek_analysis
mkdir -p /home/ubuntu/zeek_scripts
mkdir -p /home/ubuntu/lab

# Verify directories
if [ -d /home/ubuntu/zeek_analysis ]; then
    echo "✓ zeek_analysis directory created"
else
    echo "✗ Failed to create zeek_analysis directory"
    echo "  Trying with sudo..."
    sudo mkdir -p /home/ubuntu/zeek_analysis
    sudo chown ubuntu:ubuntu /home/ubuntu/zeek_analysis
fi

if [ -d /home/ubuntu/zeek_scripts ]; then
    echo "✓ zeek_scripts directory created"
else
    echo "✗ Failed to create zeek_scripts directory"
    echo "  Trying with sudo..."
    sudo mkdir -p /home/ubuntu/zeek_scripts
    sudo chown ubuntu:ubuntu /home/ubuntu/zeek_scripts
fi

# Change to zeek_analysis directory
cd /home/ubuntu/zeek_analysis
echo
echo "Current directory: $(pwd)"

# Check for PCAP files
echo
echo "Checking for PCAP files..."
VALID_PCAPS=0
for pcap in suspicious_traffic.pcap normal_traffic.pcap sample_malware_conn.pcap; do
    if [ -f "$pcap" ]; then
        SIZE=$(stat -c%s "$pcap" 2>/dev/null || echo "0")
        if [ "$SIZE" -gt "1000" ]; then
            VALID_PCAPS=$((VALID_PCAPS + 1))
        fi
    fi
done

if [ $VALID_PCAPS -eq 3 ]; then
    echo "✓ All PCAP files found and valid:"
    ls -lh *.pcap
else
    echo "✗ Missing PCAP files. Creating traffic captures..."
    
    # Use Python to create PCAP files - FIXED VERSION
    echo "Generating network traffic data..."
    python3 << 'EOF'
import sys
import struct
import time

def write_pcap_header(f):
    """Write PCAP global header"""
    f.write(struct.pack('<IHHIIII', 
        0xa1b2c3d4,  # Magic number
        2, 4,        # Version  
        0, 0,        # Timezone, accuracy
        65535,       # Snaplen
        1            # Ethernet
    ))

def create_packet(src_ip, dst_ip, src_port, dst_port, tcp_flags='S'):
    """Create a simple Ethernet/IP/TCP packet"""
    # Ethernet header (14 bytes)
    eth = b'\x00' * 6 + b'\x00' * 6 + b'\x08\x00'
    
    # IP header (20 bytes)
    ip_hdr = b'\x45\x00\x00\x28'  # Version/IHL, ToS, Total Length (40)
    ip_hdr += b'\x00\x01\x40\x00'  # ID, Flags/Fragment, TTL
    ip_hdr += b'\x40\x06'  # TTL=64, Protocol=TCP
    
    # Calculate IP checksum (simplified - set to 0 for now)
    ip_hdr += b'\x00\x00'
    
    # Source and destination IPs
    src_bytes = bytes(map(int, src_ip.split('.')))
    dst_bytes = bytes(map(int, dst_ip.split('.')))
    ip_hdr += src_bytes + dst_bytes
    
    # TCP header (20 bytes minimum)
    tcp_hdr = struct.pack('!HH', src_port, dst_port)  # Ports
    tcp_hdr += struct.pack('!I', 1000)  # Sequence number
    tcp_hdr += struct.pack('!I', 0)     # Ack number
    tcp_hdr += b'\x50'  # Data offset (5 * 4 = 20 bytes)
    
    # TCP flags
    flags = 0
    if 'S' in tcp_flags: flags |= 0x02  # SYN
    if 'A' in tcp_flags: flags |= 0x10  # ACK
    if 'R' in tcp_flags: flags |= 0x04  # RST
    if 'F' in tcp_flags: flags |= 0x01  # FIN
    if 'P' in tcp_flags: flags |= 0x08  # PSH
    
    tcp_hdr += bytes([flags])
    tcp_hdr += struct.pack('!H', 8192)  # Window
    tcp_hdr += b'\x00\x00'  # Checksum (0 for simplicity)
    tcp_hdr += b'\x00\x00'  # Urgent pointer
    
    return eth + ip_hdr + tcp_hdr

def write_packet(f, packet, timestamp=None):
    """Write a packet to PCAP file"""
    if timestamp is None:
        timestamp = int(time.time())
    
    # PCAP packet header
    f.write(struct.pack('<IIII',
        timestamp, 0,      # Timestamp
        len(packet),       # Captured length
        len(packet)        # Original length
    ))
    f.write(packet)

# Create suspicious_traffic.pcap
print("  Creating suspicious_traffic.pcap...")
with open('suspicious_traffic.pcap', 'wb') as f:
    write_pcap_header(f)
    
    # Port scanning from 192.168.1.100
    scanner_ip = "192.168.1.100"
    target_ip = "10.0.0.5"
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]
    
    for port in scan_ports:
        # SYN packet (scan attempt)
        pkt = create_packet(scanner_ip, target_ip, 45678, port, 'S')
        write_packet(f, pkt)
        
        # Some ports respond with SYN-ACK
        if port in [22, 80, 443]:
            pkt = create_packet(target_ip, scanner_ip, port, 45678, 'SA')
            write_packet(f, pkt)
            # Scanner sends RST
            pkt = create_packet(scanner_ip, target_ip, 45678, port, 'R')
            write_packet(f, pkt)
        else:
            # Port closed - RST response
            pkt = create_packet(target_ip, scanner_ip, port, 45678, 'RA')
            write_packet(f, pkt)
    
    # SSH brute force attempts from 203.0.113.50
    attacker_ip = "203.0.113.50"
    ssh_target = "10.0.0.10"
    
    for i in range(20):
        sport = 40000 + i
        # Connection attempts
        pkt = create_packet(attacker_ip, ssh_target, sport, 22, 'S')
        write_packet(f, pkt)
        pkt = create_packet(ssh_target, attacker_ip, 22, sport, 'SA')
        write_packet(f, pkt)
        pkt = create_packet(attacker_ip, ssh_target, sport, 22, 'A')
        write_packet(f, pkt)
        # Quick disconnect (failed auth)
        pkt = create_packet(ssh_target, attacker_ip, 22, sport, 'FA')
        write_packet(f, pkt)
        pkt = create_packet(attacker_ip, ssh_target, sport, 22, 'A')
        write_packet(f, pkt)
    
    # HTTP with SQL injection
    http_attacker = "192.168.1.150"
    web_server = "10.0.0.80"
    pkt = create_packet(http_attacker, web_server, 54321, 80, 'SPA')
    write_packet(f, pkt)
    
    # Directory traversal attempt
    pkt = create_packet(http_attacker, web_server, 54322, 80, 'SPA')
    write_packet(f, pkt)
    
    # DNS queries (port 53)
    for i in range(5):
        pkt = create_packet("192.168.1.200", "8.8.8.8", 50000+i, 53, 'S')
        write_packet(f, pkt)
    
    # Protocol mismatch - plain HTTP on port 443
    pkt = create_packet("192.168.1.75", "10.0.0.443", 35000, 443, 'SPA')
    write_packet(f, pkt)

print("  Created suspicious_traffic.pcap")

# Create normal_traffic.pcap  
print("  Creating normal_traffic.pcap...")
with open('normal_traffic.pcap', 'wb') as f:
    write_pcap_header(f)
    
    # Normal web traffic
    for i in range(10):
        client = f"192.168.1.{100+i}"
        server = "93.184.216.34"  # example.com
        sport = 50000 + i
        
        # Full connection
        pkt = create_packet(client, server, sport, 80, 'S')
        write_packet(f, pkt)
        pkt = create_packet(server, client, 80, sport, 'SA')
        write_packet(f, pkt)
        pkt = create_packet(client, server, sport, 80, 'A')
        write_packet(f, pkt)
        pkt = create_packet(client, server, sport, 80, 'PA')
        write_packet(f, pkt)
        pkt = create_packet(server, client, 80, sport, 'PA')
        write_packet(f, pkt)
        pkt = create_packet(client, server, sport, 80, 'FA')
        write_packet(f, pkt)
        pkt = create_packet(server, client, 80, sport, 'FA')
        write_packet(f, pkt)
    
    # Normal DNS
    for i in range(5):
        client = f"192.168.1.{110+i}"
        pkt = create_packet(client, "8.8.8.8", 40000+i, 53, 'S')
        write_packet(f, pkt)
        pkt = create_packet("8.8.8.8", client, 53, 40000+i, 'SA')
        write_packet(f, pkt)
    
    # HTTPS connections
    for i in range(5):
        client = f"192.168.1.{120+i}"
        sport = 45000 + i
        pkt = create_packet(client, "142.250.80.46", sport, 443, 'S')
        write_packet(f, pkt)
        pkt = create_packet("142.250.80.46", client, 443, sport, 'SA')
        write_packet(f, pkt)
        pkt = create_packet(client, "142.250.80.46", sport, 443, 'A')
        write_packet(f, pkt)

print("  Created normal_traffic.pcap")

# Create sample_malware_conn.pcap
print("  Creating sample_malware_conn.pcap...")
with open('sample_malware_conn.pcap', 'wb') as f:
    write_pcap_header(f)
    
    c2_client = "192.168.1.55"
    c2_server = "185.220.101.45"
    
    # Regular beacon connections (every 60 seconds)
    base_time = int(time.time())
    for i in range(10):
        sport = 40000 + i
        timestamp = base_time + (i * 60)  # 60 second intervals
        
        # Beacon connection
        pkt = create_packet(c2_client, c2_server, sport, 4444, 'S')
        write_packet(f, pkt, timestamp)
        pkt = create_packet(c2_server, c2_client, 4444, sport, 'SA')
        write_packet(f, pkt, timestamp)
        pkt = create_packet(c2_client, c2_server, sport, 4444, 'PA')
        write_packet(f, pkt, timestamp)
        pkt = create_packet(c2_server, c2_client, 4444, sport, 'PA')
        write_packet(f, pkt, timestamp)
        pkt = create_packet(c2_client, c2_server, sport, 4444, 'FA')
        write_packet(f, pkt, timestamp)

print("  Created sample_malware_conn.pcap")
print("  Successfully created all PCAP files")
EOF
    
    # Set ownership
    sudo chown ubuntu:ubuntu *.pcap 2>/dev/null
    chmod 644 *.pcap 2>/dev/null
    
    echo
    echo "✓ Created PCAP files:"
    ls -lh *.pcap
fi

# Check for Zeek
echo
echo "Checking for Zeek installation..."
if command -v zeek &> /dev/null; then
    echo "✓ Zeek is installed: $(which zeek)"
    ZEEK_CMD="zeek"
elif command -v bro &> /dev/null; then
    echo "✓ Bro (legacy Zeek) is installed: $(which bro)"
    ZEEK_CMD="bro"
else
    echo "✗ Zeek is not installed"
    echo "  Please use Ubuntu Desktop environment where Zeek is pre-installed"
    ZEEK_CMD="echo 'Zeek not installed'"
fi

# Check for zeek-cut and create if missing
echo
echo "Checking for zeek-cut..."
if ! command -v zeek-cut &> /dev/null; then
    echo "✗ zeek-cut not found. Creating proper implementation..."
    
    # Create a working zeek-cut script
    cat << 'ZEEKCUT' | sudo tee /usr/local/bin/zeek-cut > /dev/null
#!/usr/bin/env python3
import sys
import argparse

def main():
    # Read field names from command line
    fields = sys.argv[1:]
    
    if not fields:
        # If no fields specified, pass through everything
        for line in sys.stdin:
            print(line.rstrip())
        return
    
    # Read the log file from stdin
    header_fields = []
    field_indices = []
    
    for line in sys.stdin:
        line = line.rstrip()
        
        if line.startswith('#separator'):
            continue
        elif line.startswith('#fields'):
            # Parse the field names
            parts = line.split('\t')
            header_fields = parts[1:]  # Skip the "#fields" part
            
            # Find indices for requested fields
            for field in fields:
                if field in header_fields:
                    field_indices.append(header_fields.index(field))
                else:
                    field_indices.append(-1)
        elif line.startswith('#'):
            continue
        else:
            # Process data lines
            parts = line.split('\t')
            output = []
            for idx in field_indices:
                if idx >= 0 and idx < len(parts):
                    output.append(parts[idx])
                else:
                    output.append('-')
            print('\t'.join(output))

if __name__ == '__main__':
    main()
ZEEKCUT
    
    sudo chmod +x /usr/local/bin/zeek-cut
    echo "✓ Created zeek-cut at /usr/local/bin/zeek-cut"
else
    echo "✓ zeek-cut is available"
fi

# Copy Zeek scripts
echo
echo "Checking for Zeek scripts..."
if [ -d /home/ubuntu/lab ]; then
    for script in detect_scans.zeek protocol_anomaly.zeek correlation_rules.zeek; do
        if [ -f /home/ubuntu/lab/$script ]; then
            cp /home/ubuntu/lab/$script /home/ubuntu/zeek_scripts/
            echo "✓ Copied $script"
        fi
    done
fi

echo
echo "===================================="
echo "Lab initialization complete!"
echo
echo "You are now in: $(pwd)"
echo
echo "To start the lab, run:"
echo "  $ZEEK_CMD -r suspicious_traffic.pcap"
echo
echo "To use zeek-cut:"
echo "  zeek-cut id.orig_h id.resp_p < conn.log"
echo

# Check for Zeek
echo
echo "Checking for Zeek installation..."
if command -v zeek &> /dev/null; then
    echo "✓ Zeek is installed: $(which zeek)"
    ZEEK_CMD="zeek"
elif command -v bro &> /dev/null; then
    echo "✓ Bro (legacy Zeek) is installed: $(which bro)"
    ZEEK_CMD="bro"
    echo "  Creating 'zeek' alias..."
    alias zeek='bro'
else
    echo "✗ Zeek is not installed"
    echo "  To install, run: sudo apt install zeek-lts"
    echo "  Or: sudo apt install bro"
    ZEEK_CMD="echo 'Zeek not installed. Please install first.'"
fi

# Check for zeek-cut
echo
echo "Checking for zeek-cut..."
if ! command -v zeek-cut &> /dev/null; then
    echo "✗ zeek-cut not found. Creating simple alternative..."
    cat << 'EOF' > /home/ubuntu/zeek-cut
#!/bin/bash
# Simple zeek-cut alternative
awk -F'\t' '
/^#fields/ { 
    for(i=2; i<=NF; i++) field_map[$i] = i-1
}
/^#/ { next }
{
    for(i=1; i<ARGC; i++) {
        if (ARGV[i] in field_map) {
            printf "%s", $field_map[ARGV[i]]
            if (i < ARGC-1) printf "\t"
        }
    }
    printf "\n"
}' "$@"
EOF
    chmod +x /home/ubuntu/zeek-cut
    export PATH=$PATH:/home/ubuntu
    echo "✓ Created zeek-cut alternative"
else
    echo "✓ zeek-cut is available"
fi

# Copy Zeek scripts if they exist in lab directory
echo
echo "Checking for Zeek scripts..."
if [ -d /home/ubuntu/lab ]; then
    for script in detect_scans.zeek protocol_anomaly.zeek correlation_rules.zeek; do
        if [ -f /home/ubuntu/lab/$script ]; then
            cp /home/ubuntu/lab/$script /home/ubuntu/zeek_scripts/
            echo "✓ Copied $script"
        fi
    done
fi

# Create a simple test script if none exist
if [ ! -f /home/ubuntu/zeek_scripts/detect_scans.zeek ]; then
    echo "Creating sample detection script..."
    cat << 'EOF' > /home/ubuntu/zeek_scripts/detect_scans.zeek
# Simple port scan detector
@load base/frameworks/notice

module PortScan;

export {
    redef enum Notice::Type += {
        Port_Scan
    };
}

event connection_attempt(c: connection) {
    # Simple detection - just for testing
    if (c$id$resp_p == 22/tcp || c$id$resp_p == 23/tcp) {
        NOTICE([$note=Port_Scan,
                $msg=fmt("Possible scan to port %s", c$id$resp_p),
                $conn=c]);
    }
}
EOF
    echo "✓ Created sample detect_scans.zeek"
fi

echo
echo "===================================="
echo "Lab initialization complete!"
echo
echo "You are now in: $(pwd)"
echo
echo "To start the lab, run:"
echo "  $ZEEK_CMD -r suspicious_traffic.pcap"
echo
echo "To use zeek-cut:"
echo "  zeek-cut id.orig_h id.resp_p < conn.log"
echo
