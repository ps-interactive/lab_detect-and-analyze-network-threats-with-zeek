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

def create_suspicious_traffic():
    packets = []
    
    # Port scanning activity
    print("  Creating port scan traffic...")
    src = "192.168.1.100"
    for port in [21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 8080]:
        syn = IP(src=src, dst="192.168.1.10")/TCP(sport=random.randint(40000,60000), dport=port, flags="S", seq=1000)
        packets.append(syn)
        if port in [22, 80, 443]:
            syn_ack = IP(src="192.168.1.10", dst=src)/TCP(sport=port, dport=syn[TCP].sport, flags="SA", seq=2000, ack=1001)
            packets.append(syn_ack)
            rst = IP(src=src, dst="192.168.1.10")/TCP(sport=syn[TCP].sport, dport=port, flags="R", seq=1001)
            packets.append(rst)
    
    # SSH brute force attempts
    print("  Creating SSH authentication failures...")
    attacker = "203.0.113.50"
    for i in range(20):
        sport = random.randint(50000, 60000)
        syn = IP(src=attacker, dst="192.168.1.15")/TCP(sport=sport, dport=22, flags="S", seq=i*1000)
        packets.append(syn)
        syn_ack = IP(src="192.168.1.15", dst=attacker)/TCP(sport=22, dport=sport, flags="SA", seq=i*2000, ack=i*1000+1)
        packets.append(syn_ack)
        ack = IP(src=attacker, dst="192.168.1.15")/TCP(sport=sport, dport=22, flags="A", seq=i*1000+1, ack=i*2000+1)
        packets.append(ack)
        rst = IP(src="192.168.1.15", dst=attacker)/TCP(sport=22, dport=sport, flags="R", seq=i*2000+1)
        packets.append(rst)
    
    # HTTP traffic with SQL injection
    print("  Creating HTTP attack patterns...")
    payload = "GET /login.php?user=admin' OR '1'='1&pass=x HTTP/1.1\r\nHost: vulnerable.local\r\n\r\n"
    http_attack = IP(src="192.168.1.110", dst="192.168.1.30")/TCP(sport=54321, dport=80, flags="PA", seq=10000, ack=20000)/Raw(load=payload)
    packets.append(http_attack)
    
    # Directory traversal
    traversal = "GET /../../../../etc/passwd HTTP/1.1\r\nHost: target.local\r\n\r\n"
    dir_attack = IP(src="192.168.1.111", dst="192.168.1.30")/TCP(sport=54322, dport=80, flags="PA", seq=30000, ack=40000)/Raw(load=traversal)
    packets.append(dir_attack)
    
    # DNS tunneling patterns
    print("  Creating DNS tunneling traffic...")
    for i in range(5):
        long_query = "data" + "x" * 40 + str(i) + ".tunnel.evil.com"
        dns = IP(src="192.168.1.102", dst="8.8.8.8")/UDP(sport=random.randint(50000,60000), dport=53)/DNS(qd=DNSQR(qname=long_query))
        packets.append(dns)
    
    # C2 beacon traffic
    print("  Creating command and control beacons...")
    c2_server = "185.159.158.1"
    for i in range(10):
        beacon_data = f"BEACON:{i:04d}:ACTIVE:SYSINFO:HOST"
        beacon = IP(src="192.168.1.105", dst=c2_server)/TCP(sport=55555, dport=8443, flags="PA", seq=i*1000, ack=i*2000)/Raw(load=beacon_data)
        packets.append(beacon)
    
    wrpcap("suspicious_traffic.pcap", packets)
    print(f"  Created suspicious_traffic.pcap ({len(packets)} packets)")

def create_normal_traffic():
    packets = []
    
    # Normal HTTP traffic
    print("  Creating normal HTTP traffic...")
    for i in range(10):
        src = f"192.168.1.{50+i}"
        request = f"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        http = IP(src=src, dst="192.168.1.80")/TCP(sport=random.randint(50000,60000), dport=80, flags="PA", seq=i*1000, ack=i*2000)/Raw(load=request)
        packets.append(http)
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome</body></html>"
        resp = IP(src="192.168.1.80", dst=src)/TCP(sport=80, dport=http[TCP].sport, flags="PA", seq=i*2000, ack=i*1000+len(request))/Raw(load=response)
        packets.append(resp)
    
    # Normal DNS queries
    print("  Creating normal DNS queries...")
    for domain in ["google.com", "github.com", "stackoverflow.com", "microsoft.com"]:
        dns_q = IP(src="192.168.1.71", dst="192.168.1.1")/UDP(sport=random.randint(50000,60000), dport=53)/DNS(qd=DNSQR(qname=domain))
        packets.append(dns_q)
        dns_r = IP(src="192.168.1.1", dst="192.168.1.71")/UDP(sport=53, dport=dns_q[UDP].sport)/DNS(qr=1, qd=DNSQR(qname=domain), an=DNSRR(rrname=domain, rdata="93.184.216.34"))
        packets.append(dns_r)
    
    # HTTPS connections
    print("  Creating HTTPS connections...")
    for i in range(5):
        src = f"192.168.1.{61+i}"
        sport = random.randint(50000, 60000)
        syn = IP(src=src, dst="192.168.1.443")/TCP(sport=sport, dport=443, flags="S", seq=1000)
        packets.append(syn)
        syn_ack = IP(src="192.168.1.443", dst=src)/TCP(sport=443, dport=sport, flags="SA", seq=2000, ack=1001)
        packets.append(syn_ack)
        ack = IP(src=src, dst="192.168.1.443")/TCP(sport=sport, dport=443, flags="A", seq=1001, ack=2001)
        packets.append(ack)
    
    wrpcap("normal_traffic.pcap", packets)
    print(f"  Created normal_traffic.pcap ({len(packets)} packets)")

def create_malware_traffic():
    packets = []
    
    # Malware C2 beacons
    print("  Creating malware beacon traffic...")
    c2 = "45.142.120.5"
    infected = "192.168.1.150"
    sport = 55555
    
    # Initial handshake
    syn = IP(src=infected, dst=c2)/TCP(sport=sport, dport=4444, flags="S", seq=1000)
    packets.append(syn)
    syn_ack = IP(src=c2, dst=infected)/TCP(sport=4444, dport=sport, flags="SA", seq=2000, ack=1001)
    packets.append(syn_ack)
    ack = IP(src=infected, dst=c2)/TCP(sport=sport, dport=4444, flags="A", seq=1001, ack=2001)
    packets.append(ack)
    
    # Regular beacons
    for i in range(10):
        beacon = f"BEACON:{i:04d}:HOST:WINBOX:USER:admin:STATUS:ACTIVE"
        pkt = IP(src=infected, dst=c2)/TCP(sport=sport, dport=4444, flags="PA", seq=1001+i*100, ack=2001+i*50)/Raw(load=beacon)
        packets.append(pkt)
        if i % 3 == 0:
            cmd = "CMD:SCREENSHOT" if i == 3 else "CMD:PERSIST"
            resp = IP(src=c2, dst=infected)/TCP(sport=4444, dport=sport, flags="PA", seq=2001+i*50, ack=1001+i*100+len(beacon))/Raw(load=cmd)
            packets.append(resp)
    
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

# Check for zeek-cut
echo
echo "Checking for zeek-cut..."
if command -v zeek-cut &> /dev/null; then
    echo "✓ zeek-cut is available"
else
    echo "✗ zeek-cut not found. Creating alternative..."
    cat << 'ZEEKCUT' > ~/zeek-cut
#!/bin/bash
awk -F'\t' '/^#fields/{for(i=2;i<=NF;i++)f[$i]=i-1}/^#/{next}{for(i=1;i<ARGC;i++)if(ARGV[i] in f){printf "%s",$f[ARGV[i]];if(i<ARGC-1)printf "\t"}printf "\n"}' "$@"
ZEEKCUT
    chmod +x ~/zeek-cut
    export PATH=$PATH:~
    echo "✓ Created zeek-cut alternative"
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
