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
    echo "✗ Missing or invalid PCAP files. Creating traffic captures..."
    
    # Ensure we have netcat
    which nc >/dev/null 2>&1 || sudo apt-get install -y netcat-openbsd >/dev/null 2>&1
    
    # Clean up old files
    rm -f suspicious_traffic.pcap normal_traffic.pcap sample_malware_conn.pcap 2>/dev/null
    
    # Create suspicious traffic
    echo "  Creating port scan traffic..."
    
    # Start packet capture for suspicious traffic
    sudo timeout 20 tcpdump -i lo -w suspicious_traffic.pcap >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 2
    
    # Generate port scanning pattern locally
    for port in 21 22 23 25 53 80 110 143 443 445 1433 3306 3389 8080; do
        (timeout 0.1 nc -zv 127.0.0.1 $port 2>/dev/null || true) &
    done
    
    # SSH brute force simulation (rapid connections to port 22)
    echo "  Creating SSH brute force attempts..."
    for i in {1..20}; do
        (echo "SSH-2.0-Test" | timeout 0.1 nc 127.0.0.1 22 2>/dev/null || true) &
    done
    
    # HTTP with SQL injection
    echo "  Creating HTTP attack patterns..."
    (echo -e "GET /login.php?user=admin'+OR+'1'='1 HTTP/1.1\r\nHost: vulnerable.local\r\n\r\n" | \
        timeout 0.2 nc 127.0.0.1 80 2>/dev/null || true) &
    
    # Directory traversal
    (echo -e "GET /../../../../etc/passwd HTTP/1.1\r\nHost: target.local\r\n\r\n" | \
        timeout 0.2 nc 127.0.0.1 80 2>/dev/null || true) &
    
    # DNS patterns
    echo "  Creating DNS tunneling patterns..."
    for i in {1..5}; do
        (nslookup "verylongsubdomainxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx$i.tunnel.evil.com" 127.0.0.1 2>/dev/null || true) &
    done
    
    # Wait for traffic generation
    sleep 5
    
    # Stop capture
    sudo kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null
    
    # If suspicious_traffic.pcap is too small, use Python to create a proper one
    if [ ! -f "suspicious_traffic.pcap" ] || [ $(stat -c%s "suspicious_traffic.pcap" 2>/dev/null || echo 0) -lt 1000 ]; then
        echo "  Creating enhanced suspicious traffic with Python..."
        python3 << 'PYTHON_EOF' 2>/dev/null || true
import struct
import random
import socket

def write_pcap(filename, packets_data):
    with open(filename, 'wb') as f:
        # PCAP global header
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        
        # Write packets
        for packet in packets_data:
            # Simple Ethernet + IP + TCP structure
            eth = b'\x00' * 12 + b'\x08\x00'  # Ethernet
            
            # IP header
            ip = b'\x45\x00'  # Version, IHL
            ip += struct.pack('>H', 40)  # Total length
            ip += b'\x00\x00\x40\x00\x40\x06\x00\x00'  # ID, flags, TTL, proto
            
            # Source and dest IPs
            src_ip = socket.inet_aton(packet['src'])
            dst_ip = socket.inet_aton(packet['dst'])
            ip += src_ip + dst_ip
            
            # TCP header
            tcp = struct.pack('>HH', packet['sport'], packet['dport'])
            tcp += b'\x00\x00\x00\x00' * 2  # Seq, Ack
            tcp += b'\x50\x02\x00\x00\x00\x00\x00\x00'  # Flags, window, etc
            
            pkt = eth + ip + tcp
            
            # PCAP packet header
            f.write(struct.pack('<IIII', 0, 0, len(pkt), len(pkt)))
            f.write(pkt)

# Generate suspicious traffic patterns
packets = []

# Port scanning from 192.168.1.100
for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080]:
    packets.append({'src': '192.168.1.100', 'dst': '10.0.0.5', 
                   'sport': random.randint(40000, 60000), 'dport': port})

# SSH brute force from 203.0.113.50
for i in range(20):
    packets.append({'src': '203.0.113.50', 'dst': '10.0.0.10',
                   'sport': 50000 + i, 'dport': 22})

# HTTP attacks
packets.append({'src': '192.168.1.150', 'dst': '10.0.0.80',
               'sport': 54321, 'dport': 80})

write_pcap('suspicious_traffic.pcap', packets)
print("    Created suspicious_traffic.pcap with Python")
PYTHON_EOF
    fi
    
    # Create normal traffic
    echo "  Creating normal web traffic..."
    sudo timeout 10 tcpdump -i lo -w normal_traffic.pcap >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 2
    
    # Normal HTTP traffic
    for i in {1..10}; do
        (echo -e "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n" | \
            timeout 0.2 nc 127.0.0.1 80 2>/dev/null || true) &
    done
    
    # Normal DNS
    for domain in google.com github.com stackoverflow.com; do
        (nslookup $domain 127.0.0.1 2>/dev/null || true) &
    done
    
    sleep 3
    sudo kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null
    
    # Create C2 beacon traffic
    echo "  Creating C2 beacon traffic..."
    sudo timeout 15 tcpdump -i lo -w sample_malware_conn.pcap >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 2
    
    # Regular beacon pattern
    for i in {1..10}; do
        (echo "BEACON:$(printf '%04d' $i):STATUS" | \
            timeout 0.2 nc 127.0.0.1 4444 2>/dev/null || true) &
        sleep 0.5
    done
    
    sleep 3
    sudo kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null
    
    # Ensure minimum valid PCAP files
    for pcap in suspicious_traffic.pcap normal_traffic.pcap sample_malware_conn.pcap; do
        if [ ! -f "$pcap" ] || [ ! -s "$pcap" ]; then
            echo "  Warning: $pcap missing or empty, creating minimal valid file..."
            # Create minimal valid PCAP with header
            printf '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' > $pcap
        fi
        SIZE=$(stat -c%s "$pcap" 2>/dev/null || echo "0")
        echo "  Created $pcap (${SIZE} bytes)"
    done
    
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
