#!/usr/bin/env python3
"""
Generate sample network traffic PCAP files for Zeek analysis lab
Creates both suspicious and normal traffic patterns
"""

import sys
import random

try:
    from scapy.all import *
except ImportError:
    print("Scapy not installed. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
    from scapy.all import *

def generate_suspicious_traffic():
    """Generate suspicious network traffic patterns"""
    packets = []
    
    # Port scan pattern - TCP SYN scan
    print("Generating port scan traffic...")
    src_ip = "192.168.1.100"
    dst_ip = "192.168.1.10"
    for port in [21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 8080]:
        # SYN packet
        syn = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024,65535), dport=port, flags="S")
        packets.append(syn)
        # Simulate no response for most ports (closed)
        if port in [22, 80, 443]:
            # SYN-ACK response for open ports
            syn_ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=port, dport=syn[TCP].sport, flags="SA", ack=syn[TCP].seq+1)
            packets.append(syn_ack)
            # RST to close connection (scanner behavior)
            rst = IP(src=src_ip, dst=dst_ip)/TCP(sport=syn[TCP].sport, dport=port, flags="R")
            packets.append(rst)
    
    # Brute force attempt - SSH
    print("Generating brute force traffic...")
    attacker_ip = "203.0.113.50"
    target_ip = "192.168.1.15"
    for attempt in range(20):
        # Multiple rapid SSH connection attempts
        sport = random.randint(40000, 50000)
        syn = IP(src=attacker_ip, dst=target_ip)/TCP(sport=sport, dport=22, flags="S")
        packets.append(syn)
        syn_ack = IP(src=target_ip, dst=attacker_ip)/TCP(sport=22, dport=sport, flags="SA")
        packets.append(syn_ack)
        ack = IP(src=attacker_ip, dst=target_ip)/TCP(sport=sport, dport=22, flags="A")
        packets.append(ack)
        # Failed auth (connection reset)
        rst = IP(src=target_ip, dst=attacker_ip)/TCP(sport=22, dport=sport, flags="R")
        packets.append(rst)
    
    # Protocol mismatch - HTTP on HTTPS port
    print("Generating protocol mismatch traffic...")
    http_request = IP(src="192.168.1.101", dst="192.168.1.20")/TCP(sport=45678, dport=443, flags="PA")/Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    packets.append(http_request)
    
    # DNS tunneling attempt
    print("Generating DNS tunneling traffic...")
    for i in range(10):
        # Unusually long DNS queries (potential data exfiltration)
        long_domain = "data" + "x" * 50 + str(i) + ".tunnel.evil.com"
        dns_query = IP(src="192.168.1.102", dst="8.8.8.8")/UDP(sport=random.randint(1024,65535), dport=53)/DNS(qd=DNSQR(qname=long_domain))
        packets.append(dns_query)
    
    # Suspicious outbound connection at odd hours
    print("Generating C2 beacon traffic...")
    c2_ip = "185.159.158.1"  # Simulated C2 server
    for i in range(5):
        # Periodic beacons
        beacon = IP(src="192.168.1.105", dst=c2_ip)/TCP(sport=random.randint(1024,65535), dport=8443, flags="PA")/Raw(load="beacon_" + str(i))
        packets.append(beacon)
    
    # SQL injection attempt
    print("Generating SQL injection traffic...")
    sql_payload = "GET /login.php?user=admin' OR '1'='1&password=x HTTP/1.1\r\nHost: vulnerable.local\r\n\r\n"
    sqli = IP(src="192.168.1.110", dst="192.168.1.30")/TCP(sport=54321, dport=80, flags="PA")/Raw(load=sql_payload)
    packets.append(sqli)
    
    # Directory traversal attempt
    dir_traversal = "GET /../../../../etc/passwd HTTP/1.1\r\nHost: target.local\r\n\r\n"
    traversal = IP(src="192.168.1.111", dst="192.168.1.30")/TCP(sport=54322, dport=80, flags="PA")/Raw(load=dir_traversal)
    packets.append(traversal)
    
    # Missing HTTP Host header (anomaly)
    bad_http = IP(src="192.168.1.112", dst="192.168.1.40")/TCP(sport=55555, dport=80, flags="PA")/Raw(load="GET / HTTP/1.1\r\n\r\n")
    packets.append(bad_http)
    
    # Write suspicious traffic PCAP
    wrpcap("/home/ubuntu/zeek_analysis/suspicious_traffic.pcap", packets)
    print(f"Generated suspicious_traffic.pcap with {len(packets)} packets")

def generate_normal_traffic():
    """Generate normal network traffic patterns"""
    packets = []
    
    # Normal HTTP traffic
    print("Generating normal HTTP traffic...")
    for i in range(10):
        src_ip = f"192.168.1.{random.randint(50, 60)}"
        # Normal HTTP GET request
        http_get = IP(src=src_ip, dst="192.168.1.80")/TCP(sport=random.randint(1024,65535), dport=80, flags="PA")/Raw(load=f"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
        packets.append(http_get)
        # HTTP response
        http_response = IP(src="192.168.1.80", dst=src_ip)/TCP(sport=80, dport=http_get[TCP].sport, flags="PA")/Raw(load="HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n<html>...</html>")
        packets.append(http_response)
    
    # Normal HTTPS traffic (just handshake)
    print("Generating normal HTTPS traffic...")
    for i in range(5):
        src_ip = f"192.168.1.{random.randint(61, 70)}"
        sport = random.randint(1024, 65535)
        # TLS handshake
        syn = IP(src=src_ip, dst="192.168.1.443")/TCP(sport=sport, dport=443, flags="S")
        packets.append(syn)
        syn_ack = IP(src="192.168.1.443", dst=src_ip)/TCP(sport=443, dport=sport, flags="SA")
        packets.append(syn_ack)
        ack = IP(src=src_ip, dst="192.168.1.443")/TCP(sport=sport, dport=443, flags="A")
        packets.append(ack)
    
    # Normal DNS queries
    print("Generating normal DNS traffic...")
    domains = ["google.com", "github.com", "stackoverflow.com", "microsoft.com", "amazon.com"]
    for domain in domains:
        dns_query = IP(src="192.168.1.71", dst="192.168.1.1")/UDP(sport=random.randint(1024,65535), dport=53)/DNS(qd=DNSQR(qname=domain))
        packets.append(dns_query)
        # DNS response
        dns_response = IP(src="192.168.1.1", dst="192.168.1.71")/UDP(sport=53, dport=dns_query[UDP].sport)/DNS(qr=1, qd=DNSQR(qname=domain), an=DNSRR(rrname=domain, rdata="93.184.216.34"))
        packets.append(dns_response)
    
    # Normal SSH session
    print("Generating normal SSH traffic...")
    ssh_src = "192.168.1.75"
    ssh_dst = "192.168.1.22"
    ssh_sport = 48765
    # Proper three-way handshake
    syn = IP(src=ssh_src, dst=ssh_dst)/TCP(sport=ssh_sport, dport=22, flags="S")
    packets.append(syn)
    syn_ack = IP(src=ssh_dst, dst=ssh_src)/TCP(sport=22, dport=ssh_sport, flags="SA")
    packets.append(syn_ack)
    ack = IP(src=ssh_src, dst=ssh_dst)/TCP(sport=ssh_sport, dport=22, flags="A")
    packets.append(ack)
    # Some SSH data packets
    for i in range(5):
        data = IP(src=ssh_src, dst=ssh_dst)/TCP(sport=ssh_sport, dport=22, flags="PA")/Raw(load=b"\x00" * 50)
        packets.append(data)
    
    # Write normal traffic PCAP
    wrpcap("/home/ubuntu/zeek_analysis/normal_traffic.pcap", packets)
    print(f"Generated normal_traffic.pcap with {len(packets)} packets")

def generate_malware_traffic():
    """Generate sample malware communication patterns"""
    packets = []
    
    # Simulated malware beacon with regular intervals
    print("Generating malware beacon traffic...")
    c2_server = "45.142.120.5"
    infected_host = "192.168.1.150"
    
    for i in range(10):
        # Regular beacon every 60 seconds (simulated)
        beacon_data = f"BEACON:{i:04d}:STATUS:ACTIVE"
        beacon = IP(src=infected_host, dst=c2_server)/TCP(sport=random.randint(40000,50000), dport=4444, flags="PA")/Raw(load=beacon_data.encode())
        packets.append(beacon)
        
        # C2 response with commands
        if i % 3 == 0:
            command = f"CMD:EXFIL:DATA_{i}"
            response = IP(src=c2_server, dst=infected_host)/TCP(sport=4444, dport=beacon[TCP].sport, flags="PA")/Raw(load=command.encode())
            packets.append(response)
    
    # Write malware traffic PCAP
    wrpcap("/home/ubuntu/zeek_analysis/sample_malware_conn.pcap", packets)
    print(f"Generated sample_malware_conn.pcap with {len(packets)} packets")

if __name__ == "__main__":
    print("Starting PCAP generation for Zeek analysis lab...")
    generate_suspicious_traffic()
    generate_normal_traffic()
    generate_malware_traffic()
    print("PCAP generation complete!")
