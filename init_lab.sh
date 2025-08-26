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
    
    # Use Python to create PCAP files with scapy
    echo "Generating network traffic data..."
    python3 << 'EOF'
import sys
try:
    from scapy.all import *
except ImportError:
    print("Installing required packages...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "scapy"])
    from scapy.all import *

import random
import time

def create_suspicious_traffic():
    packets = []
    
    # Port scanning activity - ensure proper packet structure
    print("  Creating port scan traffic...")
    src = "192.168.1.100"
    target = "10.0.0.5"
    
    for port in [21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 8080]:
        sport = random.randint(40000, 60000)
        # Create proper Ethernet/IP/TCP packets
        pkt = Ether()/IP(src=src, dst=target)/TCP(sport=sport, dport=port, flags="S")
        packets.append(pkt)
        # Add response for some ports
        if port in [22, 80, 443]:
            resp = Ether()/IP(src=target, dst=src)/TCP(sport=port, dport=sport, flags="SA")
            packets.append(resp)
            rst = Ether()/IP(src=src, dst=target)/TCP(sport=sport, dport=port, flags="R")
            packets.append(rst)
        else:
            # Port closed
            rst = Ether()/IP(src=target, dst=src)/TCP(sport=port, dport=sport, flags="RA")
            packets.append(rst)
    
    # SSH brute force attempts
    print("  Creating SSH brute force attempts...")
    attacker = "203.0.113.50"
    ssh_target = "10.0.0.10"
    
    for i in range(20):
        sport = random.randint(50000, 60000)
        # Full TCP handshake
        syn = Ether()/IP(src=attacker, dst=ssh_target)/TCP(sport=sport, dport=22, flags="S")
        packets.append(syn)
        syn_ack = Ether()/IP(src=ssh_target, dst=attacker)/TCP(sport=22, dport=sport, flags="SA")
        packets.append(syn_ack)
        ack = Ether()/IP(src=attacker, dst=ssh_target)/TCP(sport=sport, dport=22, flags="A")
        packets.append(ack)
        # Quick termination (failed auth)
        fin = Ether()/IP(src=ssh_target, dst=attacker)/TCP(sport=22, dport=sport, flags="FA")
        packets.append(fin)
        ack2 = Ether()/IP(src=attacker, dst=ssh_target)/TCP(sport=sport, dport=22, flags="A")
        packets.append(ack2)
    
    # HTTP with SQL injection
    print("  Creating HTTP attack patterns...")
    http_attacker = "192.168.1.150"
    web_server = "10.0.0.80"
    sport = 54321
    
    # TCP handshake for HTTP
    syn = Ether()/IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=80, flags="S")
    packets.append(syn)
    syn_ack = Ether()/IP(src=web_server, dst=http_attacker)/TCP(sport=80, dport=sport, flags="SA")
    packets.append(syn_ack)
    ack = Ether()/IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=80, flags="A")
    packets.append(ack)
    
    # HTTP request with SQL injection
    payload = b"GET /login.php?user=admin' OR '1'='1&pass=x HTTP/1.1\r\nHost: vulnerable.local\r\n\r\n"
    http_req = Ether()/IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=payload)
    packets.append(http_req)
    
    # Directory traversal
    sport2 = 54322
    syn = Ether()/IP(src="192.168.1.111", dst=web_server)/TCP(sport=sport2, dport=80, flags="S")
    packets.append(syn)
    syn_ack = Ether()/IP(src=web_server, dst="192.168.1.111")/TCP(sport=80, dport=sport2, flags="SA")
    packets.append(syn_ack)
    ack = Ether()/IP(src="192.168.1.111", dst=web_server)/TCP(sport=sport2, dport=80, flags="A")
    packets.append(ack)
    
    traversal = b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: target.local\r\n\r\n"
    dir_req = Ether()/IP(src="192.168.1.111", dst=web_server)/TCP(sport=sport2, dport=80, flags="PA")/Raw(load=traversal)
    packets.append(dir_req)
    
    # DNS tunneling
    print("  Creating DNS tunneling traffic...")
    for i in range(5):
        long_query = "data" + "x" * 40 + str(i) + ".tunnel.evil.com"
        dns_pkt = Ether()/IP(src="192.168.1.102", dst="8.8.8.8")/UDP(sport=random.randint(50000,60000), dport=53)/DNS(qd=DNSQR(qname=long_query))
        packets.append(dns_pkt)
    
    # Write PCAP
    wrpcap("suspicious_traffic.pcap", packets)
    print(f"  Created suspicious_traffic.pcap ({len(packets)} packets)")

def create_normal_traffic():
    packets = []
    
    # Normal HTTP traffic
    print("  Creating normal HTTP traffic...")
    for i in range(10):
        src = f"192.168.1.{50+i}"
        dst = "93.184.216.34"
        sport = random.randint(50000, 60000)
        
        # Full connection
        syn = Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=80, flags="S")
        packets.append(syn)
        syn_ack = Ether()/IP(src=dst, dst=src)/TCP(sport=80, dport=sport, flags="SA")
        packets.append(syn_ack)
        ack = Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=80, flags="A")
        packets.append(ack)
        
        # HTTP request
        request = b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        http_req = Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=request)
        packets.append(http_req)
        
        # Connection termination
        fin = Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=80, flags="FA")
        packets.append(fin)
        fin_ack = Ether()/IP(src=dst, dst=src)/TCP(sport=80, dport=sport, flags="FA")
        packets.append(fin_ack)
    
    # Normal DNS
    print("  Creating normal DNS queries...")
    for domain in ["google.com", "github.com", "stackoverflow.com"]:
        src = "192.168.1.71"
        dns_q = Ether()/IP(src=src, dst="8.8.8.8")/UDP(sport=random.randint(50000,60000), dport=53)/DNS(qd=DNSQR(qname=domain))
        packets.append(dns_q)
    
    wrpcap("normal_traffic.pcap", packets)
    print(f"  Created normal_traffic.pcap ({len(packets)} packets)")

def create_malware_traffic():
    packets = []
    
    # C2 beacon traffic
    print("  Creating malware beacon traffic...")
    c2 = "185.220.101.45"
    infected = "192.168.1.55"
    sport = 45678
    
    # Regular beacons at intervals
    for i in range(10):
        # Connection for each beacon
        syn = Ether()/IP(src=infected, dst=c2)/TCP(sport=sport+i, dport=4444, flags="S")
        packets.append(syn)
        syn_ack = Ether()/IP(src=c2, dst=infected)/TCP(sport=4444, dport=sport+i, flags="SA")
        packets.append(syn_ack)
        ack = Ether()/IP(src=infected, dst=c2)/TCP(sport=sport+i, dport=4444, flags="A")
        packets.append(ack)
        
        # Beacon data
        beacon = b"BEACON:" + str(i).encode() + b":HEARTBEAT:OK"
        data_pkt = Ether()/IP(src=infected, dst=c2)/TCP(sport=sport+i, dport=4444, flags="PA")/Raw(load=beacon)
        packets.append(data_pkt)
        
        # Close connection
        fin = Ether()/IP(src=infected, dst=c2)/TCP(sport=sport+i, dport=4444, flags="FA")
        packets.append(fin)
    
    wrpcap("sample_malware_conn.pcap", packets)
    print(f"  Created sample_malware_conn.pcap ({len(packets)} packets)")

# Create all PCAP files
try:
    create_suspicious_traffic()
    create_normal_traffic()
    create_malware_traffic()
    print("  Successfully created all PCAP files")
except Exception as e:
    print(f"  Error: {e}")
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
