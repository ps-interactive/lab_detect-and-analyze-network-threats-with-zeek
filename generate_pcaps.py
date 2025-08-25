#!/usr/bin/env python3
"""
PCAP Generation Script for Zeek Network Threat Analysis Lab
Generates realistic network traffic patterns for analysis
"""

from scapy.all import *
import random
import time
import base64
import string

def generate_suspicious_traffic():
    """Generate suspicious network traffic PCAP with various attack patterns"""
    packets = []
    
    # 1. Port Scanning Activity from 192.168.1.100
    scanner_ip = "192.168.1.100"
    target_ip = "192.168.1.50"
    
    # Vertical port scan - scanning multiple ports on single host
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
    for port in common_ports:
        # SYN packet (no response - closed port)
        syn = IP(src=scanner_ip, dst=target_ip)/TCP(sport=random.randint(40000, 65000), dport=port, flags="S", seq=random.randint(1000, 9999))
        rst = IP(src=target_ip, dst=scanner_ip)/TCP(sport=port, dport=syn[TCP].sport, flags="RA", seq=0, ack=syn[TCP].seq+1)
        packets.extend([syn, rst])
    
    # Some additional scans to other hosts (horizontal scanning)
    for i in range(51, 55):
        target = f"192.168.1.{i}"
        for port in [22, 80, 443]:
            syn = IP(src=scanner_ip, dst=target)/TCP(sport=random.randint(40000, 65000), dport=port, flags="S")
            packets.append(syn)
    
    # 2. SSH Brute Force Attack from 203.0.113.50
    attacker_ip = "203.0.113.50"
    ssh_target = "192.168.1.20"
    
    # Generate 25 rapid SSH connection attempts
    for i in range(25):
        sport = random.randint(50000, 60000)
        # Complete TCP handshake
        syn = IP(src=attacker_ip, dst=ssh_target)/TCP(sport=sport, dport=22, flags="S", seq=1000+i)
        syn_ack = IP(src=ssh_target, dst=attacker_ip)/TCP(sport=22, dport=sport, flags="SA", seq=2000+i, ack=1001+i)
        ack = IP(src=attacker_ip, dst=ssh_target)/TCP(sport=sport, dport=22, flags="A", seq=1001+i, ack=2001+i)
        
        # SSH protocol negotiation (simplified)
        ssh_data = IP(src=attacker_ip, dst=ssh_target)/TCP(sport=sport, dport=22, flags="PA", seq=1001+i, ack=2001+i)/Raw(load="SSH-2.0-OpenSSH_7.4\r\n")
        ssh_resp = IP(src=ssh_target, dst=attacker_ip)/TCP(sport=22, dport=sport, flags="PA", seq=2001+i, ack=1023+i)/Raw(load="SSH-2.0-OpenSSH_7.9\r\n")
        
        # Connection reset (failed auth)
        rst = IP(src=ssh_target, dst=attacker_ip)/TCP(sport=22, dport=sport, flags="R", seq=2023+i)
        
        packets.extend([syn, syn_ack, ack, ssh_data, ssh_resp, rst])
    
    # 3. HTTP Traffic with SQL Injection Attempts
    http_attacker = "10.0.0.15"
    web_server = "192.168.1.80"
    
    # SQL injection attempt
    sport = random.randint(40000, 50000)
    syn = IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=80, flags="S", seq=3000)
    syn_ack = IP(src=web_server, dst=http_attacker)/TCP(sport=80, dport=sport, flags="SA", seq=4000, ack=3001)
    ack = IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=80, flags="A", seq=3001, ack=4001)
    
    # HTTP request with SQL injection
    sqli_payload = "GET /login.php?user=admin'+OR+'1'='1&pass=test HTTP/1.1\r\nHost: vulnerable.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    http_req = IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=80, flags="PA", seq=3001, ack=4001)/Raw(load=sqli_payload)
    
    # HTTP response
    http_resp = IP(src=web_server, dst=http_attacker)/TCP(sport=80, dport=sport, flags="PA", seq=4001, ack=3001+len(sqli_payload))/Raw(load="HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    
    packets.extend([syn, syn_ack, ack, http_req, http_resp])
    
    # 4. Directory Traversal Attempt
    sport = random.randint(40000, 50000)
    syn = IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=80, flags="S", seq=5000)
    syn_ack = IP(src=web_server, dst=http_attacker)/TCP(sport=80, dport=sport, flags="SA", seq=6000, ack=5001)
    ack = IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=80, flags="A", seq=5001, ack=6001)
    
    traversal_payload = "GET ../../../../etc/passwd HTTP/1.1\r\nHost: vulnerable.com\r\n\r\n"
    http_req = IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=80, flags="PA", seq=5001, ack=6001)/Raw(load=traversal_payload)
    
    packets.extend([syn, syn_ack, ack, http_req])
    
    # 5. DNS Tunneling Attempt (long domain names)
    dns_attacker = "172.16.0.100"
    dns_server = "8.8.8.8"
    
    # Generate suspiciously long DNS query
    long_subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=63))
    dns_query = IP(src=dns_attacker, dst=dns_server)/UDP(sport=random.randint(40000, 50000), dport=53)/DNS(
        rd=1, 
        qd=DNSQR(qname=f"{long_subdomain}.tunnel.evil.com")
    )
    packets.append(dns_query)
    
    # 6. Protocol Mismatch - HTTP on HTTPS port
    sport = random.randint(40000, 50000)
    syn = IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=443, flags="S", seq=7000)
    syn_ack = IP(src=web_server, dst=http_attacker)/TCP(sport=443, dport=sport, flags="SA", seq=8000, ack=7001)
    ack = IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=443, flags="A", seq=7001, ack=8001)
    
    # Plain HTTP on port 443 (should be HTTPS)
    http_on_https = IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=443, flags="PA", seq=7001, ack=8001)/Raw(load="GET / HTTP/1.1\r\nHost: target.com\r\n\r\n")
    
    packets.extend([syn, syn_ack, ack, http_on_https])
    
    # 7. Missing Headers Attack
    sport = random.randint(40000, 50000)
    # HTTP/1.1 request without Host header (protocol violation)
    no_host_payload = "GET /api/data HTTP/1.1\r\n\r\n"  # Missing Host header
    no_host_req = IP(src=http_attacker, dst=web_server)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=no_host_payload)
    packets.append(no_host_req)
    
    # Add some normal traffic for contrast
    for i in range(5):
        sport = random.randint(40000, 50000)
        normal_payload = f"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        normal_req = IP(src="192.168.1.10", dst=web_server)/TCP(sport=sport, dport=80, flags="PA")/Raw(load=normal_payload)
        packets.append(normal_req)
    
    return packets

def generate_normal_traffic():
    """Generate normal, benign network traffic"""
    packets = []
    
    # Normal web browsing
    client = "192.168.1.10"
    web_server = "192.168.1.80"
    
    for i in range(10):
        sport = random.randint(40000, 50000)
        
        # Complete TCP handshake
        syn = IP(src=client, dst=web_server)/TCP(sport=sport, dport=80, flags="S", seq=1000*i)
        syn_ack = IP(src=web_server, dst=client)/TCP(sport=80, dport=sport, flags="SA", seq=2000*i, ack=1000*i+1)
        ack = IP(src=client, dst=web_server)/TCP(sport=sport, dport=80, flags="A", seq=1000*i+1, ack=2000*i+1)
        
        # Normal HTTP request
        http_req = f"GET /page{i}.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: text/html\r\n\r\n"
        data = IP(src=client, dst=web_server)/TCP(sport=sport, dport=80, flags="PA", seq=1000*i+1, ack=2000*i+1)/Raw(load=http_req)
        
        # HTTP response
        http_resp = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n<html><body>Page {i}</body></html>"
        resp = IP(src=web_server, dst=client)/TCP(sport=80, dport=sport, flags="PA", seq=2000*i+1, ack=1000*i+1+len(http_req))/Raw(load=http_resp)
        
        # Connection close
        fin = IP(src=client, dst=web_server)/TCP(sport=sport, dport=80, flags="FA", seq=1000*i+1+len(http_req), ack=2000*i+1+len(http_resp))
        fin_ack = IP(src=web_server, dst=client)/TCP(sport=80, dport=sport, flags="FA", seq=2000*i+1+len(http_resp), ack=1000*i+2+len(http_req))
        
        packets.extend([syn, syn_ack, ack, data, resp, fin, fin_ack])
    
    # Normal DNS queries
    for domain in ["google.com", "example.com", "cloudflare.com", "github.com", "stackoverflow.com"]:
        dns_query = IP(src=client, dst="8.8.8.8")/UDP(sport=random.randint(40000, 50000), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        dns_response = IP(src="8.8.8.8", dst=client)/UDP(sport=53, dport=dns_query[UDP].sport)/DNS(
            id=dns_query[DNS].id,
            qr=1,
            aa=0,
            rd=1,
            ra=1,
            qd=DNSQR(qname=domain),
            an=DNSRR(rrname=domain, rdata=f"93.184.216.{random.randint(1,254)}")
        )
        packets.extend([dns_query, dns_response])
    
    return packets

def generate_malware_beacon():
    """Generate C2 beacon traffic pattern"""
    packets = []
    
    infected_host = "192.168.1.55"
    c2_server = "185.220.101.45"
    
    # Generate regular beacon pattern (every 60 seconds, 10 times)
    for i in range(10):
        sport = 4444
        dport = 4444
        
        # TCP connection
        syn = IP(src=infected_host, dst=c2_server)/TCP(sport=sport, dport=dport, flags="S", seq=1000*i)
        syn_ack = IP(src=c2_server, dst=infected_host)/TCP(sport=dport, dport=sport, flags="SA", seq=2000*i, ack=1000*i+1)
        ack = IP(src=infected_host, dst=c2_server)/TCP(sport=sport, dport=dport, flags="A", seq=1000*i+1, ack=2000*i+1)
        
        # Beacon data (encrypted/encoded)
        beacon_data = base64.b64encode(f"BEACON:{i}:SYSINFO:OK".encode()).decode()
        data_pkt = IP(src=infected_host, dst=c2_server)/TCP(sport=sport, dport=dport, flags="PA", seq=1000*i+1, ack=2000*i+1)/Raw(load=beacon_data)
        
        # C2 response (commands)
        cmd_data = base64.b64encode(f"CMD:WAIT:60".encode()).decode()
        resp_pkt = IP(src=c2_server, dst=infected_host)/TCP(sport=dport, dport=sport, flags="PA", seq=2000*i+1, ack=1000*i+1+len(beacon_data))/Raw(load=cmd_data)
        
        # Connection close
        fin = IP(src=infected_host, dst=c2_server)/TCP(sport=sport, dport=dport, flags="F", seq=1000*i+1+len(beacon_data), ack=2000*i+1+len(cmd_data))
        
        packets.extend([syn, syn_ack, ack, data_pkt, resp_pkt, fin])
        
        # Add some timing variance to make it more realistic
        if i < 9:  # Don't add delay after last beacon
            # Zeek will see these as separate connections due to FIN
            delay_packets = []
            for _ in range(random.randint(1, 3)):
                # Add some normal traffic between beacons
                sport_normal = random.randint(40000, 50000)
                normal = IP(src=infected_host, dst="8.8.8.8")/UDP(sport=sport_normal, dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
                delay_packets.append(normal)
            packets.extend(delay_packets)
    
    return packets

# Generate and write PCAP files
if __name__ == "__main__":
    print("Generating suspicious_traffic.pcap...")
    suspicious_packets = generate_suspicious_traffic()
    wrpcap("/tmp/suspicious_traffic.pcap", suspicious_packets)
    
    print("Generating normal_traffic.pcap...")
    normal_packets = generate_normal_traffic()
    wrpcap("/tmp/normal_traffic.pcap", normal_packets)
    
    print("Generating sample_malware_conn.pcap...")
    malware_packets = generate_malware_beacon()
    wrpcap("/tmp/sample_malware_conn.pcap", malware_packets)
    
    print("PCAP files generated successfully!")
