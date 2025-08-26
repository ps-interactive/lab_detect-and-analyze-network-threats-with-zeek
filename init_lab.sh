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
    
    # Use Python to create PCAP files without scapy dependency
    echo "Generating network traffic data..."
    python3 << 'EOF'
import struct
import time
import random

def write_pcap_header(f):
    """Write PCAP global header"""
    f.write(struct.pack('<IHHIIII', 
        0xa1b2c3d4,  # Magic number
        2, 4,        # Version 2.4
        0,           # Timezone offset
        0,           # Timestamp accuracy
        65535,       # Snaplen
        1            # Ethernet
    ))

def create_packet(src_ip, dst_ip, src_port, dst_port, tcp_flags='S', payload=b''):
    """Create a simple TCP packet"""
    # Ethernet header (14 bytes)
    eth = b'\x00\x00\x00\x00\x00\x00' + b'\x00\x00\x00\x00\x00\x00' + b'\x08\x00'
    
    # IP header (20 bytes)
    ip_header = b'\x45\x00'  # Version 4, IHL 5
    ip_total_len = 20 + 20 + len(payload)  # IP + TCP + payload
    ip_header += struct.pack('>H', ip_total_len)
    ip_header += b'\x00\x00\x40\x00\x40\x06\x00\x00'  # ID, flags, TTL, protocol TCP
    
    # Convert IPs
    src_bytes = bytes(map(int, src_ip.split('.')))
    dst_bytes = bytes(map(int, dst_ip.split('.')))
    ip_header += src_bytes + dst_bytes
    
    # TCP header (20 bytes)
    tcp = struct.pack('>HH', src_port, dst_port)  # Ports
    tcp += struct.pack('>I', random.randint(1000, 100000))  # Seq
    tcp += struct.pack('>I', 0)  # Ack
    tcp += b'\x50'  # Header length
    
    # Flags
    flags = 0
    if 'S' in tcp_flags: flags |= 0x02
    if 'A' in tcp_flags: flags |= 0x10
    if 'P' in tcp_flags: flags |= 0x08
    if 'F' in tcp_flags: flags |= 0x01
    if 'R' in tcp_flags: flags |= 0x04
    tcp += bytes([flags])
    
    tcp += b'\x20\x00'  # Window
    tcp += b'\x00\x00'  # Checksum
    tcp += b'\x00\x00'  # Urgent
    
    return eth + ip_header + tcp + payload

def write_packet(f, packet, timestamp=None):
    """Write packet with PCAP packet header"""
    if timestamp is None:
        timestamp = time.time()
    
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1000000)
    
    # PCAP packet header
    f.write(struct.pack('<IIII',
        ts_sec, ts_usec,
        len(packet),
        len(packet)
    ))
    f.write(packet)

# Create suspicious_traffic.pcap
with open('suspicious_traffic.pcap', 'wb') as f:
    write_pcap_header(f)
    
    # Port scanning from 192.168.1.100
    print("  Creating port scan traffic...")
    scanner_ip = "192.168.1.100"
    target_ip = "10.0.0.5"
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]
    
    for port in ports:
        # SYN scan
        pkt = create_packet(scanner_ip, target_ip, random.randint(40000, 60000), port, 'S')
        write_packet(f, pkt)
        
        # Some ports respond
        if port in [22, 80, 443]:
            # SYN-ACK
            pkt = create_packet(target_ip, scanner_ip, port, 40000, 'SA')
            write_packet(f, pkt)
            # RST
            pkt = create_packet(scanner_ip, target_ip, 40000, port, 'R')
            write_packet(f, pkt)
        else:
            # RST (port closed)
            pkt = create_packet(target_ip, scanner_ip, port, 40000, 'R')
            write_packet(f, pkt)
    
    # SSH brute force from 203.0.113.50
    print("  Creating SSH brute force attempts...")
    for i in range(20):
        sport = 50000 + i
        pkt = create_packet("203.0.113.50", "10.0.0.10", sport, 22, 'S')
        write_packet(f, pkt)
        pkt = create_packet("10.0.0.10", "203.0.113.50", 22, sport, 'SA')
        write_packet(f, pkt)
        pkt = create_packet("203.0.113.50", "10.0.0.10", sport, 22, 'A')
        write_packet(f, pkt)
        # Connection closed quickly (auth failure)
        pkt = create_packet("10.0.0.10", "203.0.113.50", 22, sport, 'FA')
        write_packet(f, pkt)
        pkt = create_packet("203.0.113.50", "10.0.0.10", sport, 22, 'A')
        write_packet(f, pkt)
    
    # HTTP with SQL injection
    print("  Creating HTTP attack patterns...")
    payload = b"GET /login.php?user=admin' OR '1'='1 HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n"
    pkt = create_packet("192.168.1.150", "10.0.0.80", 54321, 80, 'PA', payload)
    write_packet(f, pkt)
    
    # Directory traversal
    payload = b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n"
    pkt = create_packet("192.168.1.150", "10.0.0.80", 54322, 80, 'PA', payload)
    write_packet(f, pkt)
    
    # DNS queries (UDP would need different handling, using TCP for simplicity)
    print("  Creating DNS tunneling patterns...")
    for i in range(5):
        # Long DNS-like payload
        dns_data = b"QUERY:" + b"x" * 50 + str(i).encode()
        pkt = create_packet("192.168.1.200", "8.8.8.8", 60000+i, 53, 'PA', dns_data)
        write_packet(f, pkt)
    
    # Normal mixed traffic
    print("  Adding normal traffic...")
    for i in range(5):
        client = f"192.168.1.{100+i}"
        pkt = create_packet(client, "10.0.0.80", 45000+i, 80, 'S')
        write_packet(f, pkt)
        pkt = create_packet("10.0.0.80", client, 80, 45000+i, 'SA')
        write_packet(f, pkt)
        pkt = create_packet(client, "10.0.0.80", 45000+i, 80, 'A')
        write_packet(f, pkt)

print("  Created suspicious_traffic.pcap")

# Create normal_traffic.pcap
with open('normal_traffic.pcap', 'wb') as f:
    write_pcap_header(f)
    
    print("  Creating normal web traffic...")
    for i in range(10):
        client = f"192.168.1.{100+i}"
        sport = 50000 + i
        
        # HTTP connection
        pkt = create_packet(client, "93.184.216.34", sport, 80, 'S')
        write_packet(f, pkt)
        pkt = create_packet("93.184.216.34", client, 80, sport, 'SA')
        write_packet(f, pkt)
        pkt = create_packet(client, "93.184.216.34", sport, 80, 'A')
        write_packet(f, pkt)
        
        # HTTP request
        request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        pkt = create_packet(client, "93.184.216.34", sport, 80, 'PA', request)
        write_packet(f, pkt)
        
        # Close
        pkt = create_packet(client, "93.184.216.34", sport, 80, 'FA')
        write_packet(f, pkt)
        pkt = create_packet("93.184.216.34", client, 80, sport, 'FA')
        write_packet(f, pkt)
    
    # HTTPS connections
    for i in range(5):
        client = f"192.168.1.{110+i}"
        sport = 55000 + i
        pkt = create_packet(client, "142.250.80.46", sport, 443, 'S')
        write_packet(f, pkt)
        pkt = create_packet("142.250.80.46", client, 443, sport, 'SA')
        write_packet(f, pkt)
        pkt = create_packet(client, "142.250.80.46", sport, 443, 'A')
        write_packet(f, pkt)

print("  Created normal_traffic.pcap")

# Create sample_malware_conn.pcap
with open('sample_malware_conn.pcap', 'wb') as f:
    write_pcap_header(f)
    
    print("  Creating C2 beacon traffic...")
    c2_ip = "185.220.101.45"
    infected_ip = "192.168.1.55"
    
    # Regular beacons at intervals
    base_time = time.time()
    for i in range(10):
        timestamp = base_time + (i * 60)  # 60 second intervals
        sport = 40000 + i
        
        # Beacon connection
        pkt = create_packet(infected_ip, c2_ip, sport, 4444, 'S')
        write_packet(f, pkt, timestamp)
        
        pkt = create_packet(c2_ip, infected_ip, 4444, sport, 'SA')
        write_packet(f, pkt, timestamp + 0.1)
        
        pkt = create_packet(infected_ip, c2_ip, sport, 4444, 'A')
        write_packet(f, pkt, timestamp + 0.2)
        
        # Beacon data
        beacon = f"BEACON:{i:04d}:STATUS:ACTIVE".encode()
        pkt = create_packet(infected_ip, c2_ip, sport, 4444, 'PA', beacon)
        write_packet(f, pkt, timestamp + 0.3)
        
        # Close
        pkt = create_packet(infected_ip, c2_ip, sport, 4444, 'FA')
        write_packet(f, pkt, timestamp + 0.5)

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
