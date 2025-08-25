#!/bin/bash

# Initialize lab environment and generate PCAP files with realistic traffic patterns
echo "Initializing Zeek lab environment..."

# Create necessary directories
mkdir -p /home/ubuntu/zeek_analysis
mkdir -p /home/ubuntu/zeek_scripts

# Change to analysis directory
cd /home/ubuntu/zeek_analysis

# Clean up any existing files
rm -f *.pcap *.log 2>/dev/null

# Function to generate realistic network traffic data
generate_suspicious_pcap() {
    echo "Creating suspicious network traffic capture..."
    
    # Use Python with scapy to create comprehensive traffic patterns
    python3 << 'EOF'
import random
from scapy.all import *

packets = []

# Port scanning activity from 192.168.1.100
scanner_ip = "192.168.1.100"
target_ip = "10.0.0.5"

# Generate vertical port scan (many ports on single host)
common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]
for port in common_ports:
    # SYN packet (scanning)
    syn = IP(src=scanner_ip, dst=target_ip)/TCP(sport=random.randint(1024,65535), dport=port, flags="S")
    packets.append(syn)
    # Some ports respond with SYN-ACK
    if port in [22, 80, 443]:
        syn_ack = IP(src=target_ip, dst=scanner_ip)/TCP(sport=port, dport=syn[TCP].sport, flags="SA")
        packets.append(syn_ack)
        # Scanner sends RST
        rst = IP(src=scanner_ip, dst=target_ip)/TCP(sport=syn[TCP].sport, dport=port, flags="R")
        packets.append(rst)
    else:
        # Most ports send RST (closed)
        rst = IP(src=target_ip, dst=scanner_ip)/TCP(sport=port, dport=syn[TCP].sport, flags="RA")
        packets.append(rst)

# SSH brute force attempts from 203.0.113.50
attacker_ip = "203.0.113.50"
ssh_target = "10.0.0.10"

for i in range(20):
    sport = random.randint(40000, 50000)
    # SSH connection attempt
    syn = IP(src=attacker_ip, dst=ssh_target)/TCP(sport=sport, dport=22, flags="S")
    packets.append(syn)
    syn_ack = IP(src=ssh_target, dst=attacker_ip)/TCP(sport=22, dport=sport, flags="SA")
    packets.append(syn_ack)
    ack = IP(src=attacker_ip, dst=ssh_target)/TCP(sport=sport, dport=sport, flags="A")
    packets.append(ack)
    # Quick connection termination (failed auth)
    fin = IP(src=ssh_target, dst=attacker_ip)/TCP(sport=22, dport=sport, flags="FA")
    packets.append(fin)
    ack = IP(src=attacker_ip, dst=ssh_target)/TCP(sport=sport, dport=22, flags="A")
    packets.append(ack)

# HTTP with SQL injection attempt
http_attacker = "192.168.1.150"
web_server = "10.0.0.80"
sport = random.randint(50000, 60000)

# TCP handshake
syn = IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=80, flags="S")
packets.append(syn)
syn_ack = IP(src=web_server, dst=http_attacker)/TCP(sport=80, dport=sport, flags="SA")
packets.append(syn_ack)
ack = IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=80, flags="A")
packets.append(ack)

# HTTP request with SQL injection
http_payload = b"GET /login.php?user=admin'+OR+'1'='1 HTTP/1.1\r\nHost: vulnerable.site\r\n\r\n"
http_req = IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=http_payload)
packets.append(http_req)

# Directory traversal attempt
dir_payload = b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: vulnerable.site\r\n\r\n"
sport2 = random.randint(60000, 65000)
syn = IP(src=http_attacker, dst=web_server)/TCP(sport=sport2, dport=80, flags="S")
packets.append(syn)
syn_ack = IP(src=web_server, dst=http_attacker)/TCP(sport=80, dport=sport2, flags="SA")
packets.append(syn_ack)
ack = IP(src=http_attacker, dst=web_server)/TCP(sport=sport2, dport=80, flags="A")
packets.append(ack)
dir_req = IP(src=http_attacker, dst=web_server)/TCP(sport=sport2, dport=80, flags="PA")/Raw(load=dir_payload)
packets.append(dir_req)

# DNS tunneling attempt (long domain)
dns_payload = "very-long-subdomain-that-looks-like-data-exfiltration-attempt-with-encoded-content.suspicious-domain.com"
dns_query = IP(src="192.168.1.200", dst="8.8.8.8")/UDP(sport=random.randint(1024,65535), dport=53)/DNS(qd=DNSQR(qname=dns_payload))
packets.append(dns_query)

# Some normal traffic mixed in
for i in range(5):
    # Normal HTTP
    client = f"192.168.1.{random.randint(10,50)}"
    sport = random.randint(40000, 60000)
    syn = IP(src=client, dst="10.0.0.80")/TCP(sport=sport, dport=80, flags="S")
    packets.append(syn)
    syn_ack = IP(src="10.0.0.80", dst=client)/TCP(sport=80, dport=sport, flags="SA")
    packets.append(syn_ack)
    ack = IP(src=client, dst="10.0.0.80")/TCP(sport=sport, dport=80, flags="A")
    packets.append(ack)
    
    # Normal DNS
    dns_query = IP(src=client, dst="8.8.8.8")/UDP(sport=random.randint(1024,65535), dport=53)/DNS(qd=DNSQR(qname="google.com"))
    packets.append(dns_query)

# Protocol mismatch - HTTP on port 443
mismatch_sport = random.randint(35000, 40000)
plain_http_on_https = IP(src="192.168.1.75", dst="10.0.0.443")/TCP(sport=mismatch_sport, dport=443, flags="PA")/Raw(load=b"GET / HTTP/1.1\r\n\r\n")
packets.append(plain_http_on_https)

# Missing headers in HTTP/1.1
bad_http = b"GET /index.html HTTP/1.1\r\n\r\n"  # Missing Host header
sport3 = random.randint(30000, 35000)
bad_req = IP(src="192.168.1.80", dst="10.0.0.80")/TCP(sport=sport3, dport=80, flags="PA")/Raw(load=bad_http)
packets.append(bad_req)

# Write PCAP
wrpcap("suspicious_traffic.pcap", packets)
print("Created suspicious_traffic.pcap with comprehensive attack patterns")
EOF
}

generate_normal_pcap() {
    echo "Creating normal network traffic capture..."
    
    python3 << 'EOF'
import random
from scapy.all import *

packets = []

# Normal web browsing
for i in range(10):
    client = f"192.168.1.{random.randint(100,200)}"
    server = "93.184.216.34"  # example.com
    sport = random.randint(50000, 60000)
    
    # Full TCP handshake
    syn = IP(src=client, dst=server)/TCP(sport=sport, dport=80, flags="S")
    packets.append(syn)
    syn_ack = IP(src=server, dst=client)/TCP(sport=80, dport=sport, flags="SA")
    packets.append(syn_ack)
    ack = IP(src=client, dst=server)/TCP(sport=sport, dport=80, flags="A")
    packets.append(ack)
    
    # HTTP request with proper headers
    http_req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n"
    req_pkt = IP(src=client, dst=server)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=http_req)
    packets.append(req_pkt)
    
    # Response ACK
    resp_ack = IP(src=server, dst=client)/TCP(sport=80, dport=sport, flags="A")
    packets.append(resp_ack)
    
    # Connection close
    fin = IP(src=client, dst=server)/TCP(sport=sport, dport=80, flags="FA")
    packets.append(fin)
    fin_ack = IP(src=server, dst=client)/TCP(sport=80, dport=sport, flags="FA")
    packets.append(fin_ack)
    ack_fin = IP(src=client, dst=server)/TCP(sport=sport, dport=80, flags="A")
    packets.append(ack_fin)

# Normal DNS queries
dns_servers = ["8.8.8.8", "1.1.1.1"]
domains = ["google.com", "facebook.com", "youtube.com", "amazon.com", "microsoft.com"]

for domain in domains:
    client = f"192.168.1.{random.randint(100,200)}"
    dns_server = random.choice(dns_servers)
    sport = random.randint(40000, 50000)
    
    query = IP(src=client, dst=dns_server)/UDP(sport=sport, dport=53)/DNS(qd=DNSQR(qname=domain))
    packets.append(query)
    
    # DNS response
    response = IP(src=dns_server, dst=client)/UDP(sport=53, dport=sport)/DNS(qr=1, qd=DNSQR(qname=domain))
    packets.append(response)

# Normal HTTPS traffic
for i in range(5):
    client = f"192.168.1.{random.randint(100,200)}"
    server = "142.250.80.46"  # google.com IP
    sport = random.randint(45000, 55000)
    
    # TCP handshake for HTTPS
    syn = IP(src=client, dst=server)/TCP(sport=sport, dport=443, flags="S")
    packets.append(syn)
    syn_ack = IP(src=server, dst=client)/TCP(sport=443, dport=sport, flags="SA")
    packets.append(syn_ack)
    ack = IP(src=client, dst=server)/TCP(sport=sport, dport=443, flags="A")
    packets.append(ack)
    
    # TLS Client Hello (simplified)
    tls_hello = IP(src=client, dst=server)/TCP(sport=sport, dport=443, flags="PA")/Raw(load=b"\x16\x03\x01")
    packets.append(tls_hello)

wrpcap("normal_traffic.pcap", packets)
print("Created normal_traffic.pcap with typical network patterns")
EOF
}

generate_malware_pcap() {
    echo "Creating C2 beacon traffic capture..."
    
    python3 << 'EOF'
import random
import time
from scapy.all import *

packets = []

# C2 beacon traffic - regular intervals
c2_client = "192.168.1.55"
c2_server = "185.220.101.45"  # Suspicious IP

# Generate beacon traffic every 60 seconds (10 beacons)
base_time = time.time()
for i in range(10):
    sport = 4444  # Common C2 port
    timestamp = base_time + (i * 60)  # 60 second intervals
    
    # Beacon connection
    syn = IP(src=c2_client, dst=c2_server)/TCP(sport=random.randint(40000,50000), dport=sport, flags="S")
    syn.time = timestamp
    packets.append(syn)
    
    syn_ack = IP(src=c2_server, dst=c2_client)/TCP(sport=sport, dport=syn[TCP].sport, flags="SA")
    syn_ack.time = timestamp + 0.1
    packets.append(syn_ack)
    
    ack = IP(src=c2_client, dst=c2_server)/TCP(sport=syn[TCP].sport, dport=sport, flags="A")
    ack.time = timestamp + 0.2
    packets.append(ack)
    
    # Beacon data
    beacon_data = f"BEACON:{i:02d}:HEARTBEAT:OK".encode()
    data_pkt = IP(src=c2_client, dst=c2_server)/TCP(sport=syn[TCP].sport, dport=sport, flags="PA")/Raw(load=beacon_data)
    data_pkt.time = timestamp + 0.3
    packets.append(data_pkt)
    
    # Server response
    response = IP(src=c2_server, dst=c2_client)/TCP(sport=sport, dport=syn[TCP].sport, flags="PA")/Raw(load=b"ACK:NOCMD")
    response.time = timestamp + 0.4
    packets.append(response)
    
    # Connection close
    fin = IP(src=c2_client, dst=c2_server)/TCP(sport=syn[TCP].sport, dport=sport, flags="FA")
    fin.time = timestamp + 0.5
    packets.append(fin)

# Add some data exfiltration attempts
for i in range(3):
    sport = random.randint(30000, 40000)
    exfil_data = b"EXFIL:BASE64ENCODEDDATA" + bytes(str(i), 'utf-8') * 50
    
    syn = IP(src=c2_client, dst=c2_server)/TCP(sport=sport, dport=8443, flags="S")
    packets.append(syn)
    syn_ack = IP(src=c2_server, dst=c2_client)/TCP(sport=8443, dport=sport, flags="SA")
    packets.append(syn_ack)
    ack = IP(src=c2_client, dst=c2_server)/TCP(sport=sport, dport=8443, flags="A")
    packets.append(ack)
    
    # Large data transfer
    data_pkt = IP(src=c2_client, dst=c2_server)/TCP(sport=sport, dport=8443, flags="PA")/Raw(load=exfil_data)
    packets.append(data_pkt)

wrpcap("sample_malware_conn.pcap", packets)
print("Created sample_malware_conn.pcap with C2 beacon patterns")
EOF
}

# Generate all PCAP files
generate_suspicious_pcap
generate_normal_pcap
generate_malware_pcap

# Copy Zeek scripts from repository
if [ -d /home/ubuntu/lab ]; then
    cp /home/ubuntu/lab/*.zeek /home/ubuntu/zeek_scripts/ 2>/dev/null || true
fi

# Set proper permissions
chown -R ubuntu:ubuntu /home/ubuntu/zeek_analysis
chown -R ubuntu:ubuntu /home/ubuntu/zeek_scripts

echo "Lab initialization complete!"
echo "Generated PCAP files:"
ls -lh *.pcap
