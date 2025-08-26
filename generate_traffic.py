#!/usr/bin/env python3
"""
Generate sample network traffic PCAP files for Zeek analysis lab
Creates both suspicious and normal traffic patterns with real packet data
"""

import sys
import random

# Try to import scapy, install if needed
try:
    from scapy.all import *
except ImportError:
    print("Installing scapy...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "scapy"])
    from scapy.all import *

def generate_suspicious_traffic():
    """Generate suspicious network traffic patterns with real data"""
    packets = []
    
    print("Generating suspicious traffic patterns...")
    
    # 1. Port scan pattern - TCP SYN scan
    print("  - Port scanning pattern")
    src_ip = "192.168.1.100"
    dst_ip = "192.168.1.10"
    
    for port in [21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 8080]:
        # SYN packet
        syn = IP(src=src_ip, dst=dst_ip)/TCP(sport=random.randint(1024,65535), dport=port, flags="S", seq=1000)
        packets.append(syn)
        
        if port in [22, 80, 443]:  # Some ports respond
            # SYN-ACK response
            syn_ack = IP(src=dst_ip, dst=src_ip)/TCP(sport=port, dport=syn[TCP].sport, flags="SA", seq=2000, ack=1001)
            packets.append(syn_ack)
            # ACK
            ack = IP(src=src_ip, dst=dst_ip)/TCP(sport=syn[TCP].sport, dport=port, flags="A", seq=1001, ack=2001)
            packets.append(ack)
            # RST to close
            rst = IP(src=src_ip, dst=dst_ip)/TCP(sport=syn[TCP].sport, dport=port, flags="R", seq=1001)
            packets.append(rst)
    
    # 2. SSH Brute Force
    print("  - SSH brute force attempts")
    attacker_ip = "203.0.113.50"
    target_ip = "192.168.1.15"
    
    for attempt in range(10):
        sport = random.randint(40000, 50000)
        # Connection attempt
        syn = IP(src=attacker_ip, dst=target_ip)/TCP(sport=sport, dport=22, flags="S", seq=attempt*1000)
        packets.append(syn)
        syn_ack = IP(src=target_ip, dst=attacker_ip)/TCP(sport=22, dport=sport, flags="SA", seq=5000+attempt, ack=attempt*1000+1)
        packets.append(syn_ack)
        ack = IP(src=attacker_ip, dst=target_ip)/TCP(sport=sport, dport=22, flags="A", seq=attempt*1000+1, ack=5001+attempt)
        packets.append(ack)
        
        # SSH data exchange (failed auth)
        ssh_data = IP(src=attacker_ip, dst=target_ip)/TCP(sport=sport, dport=22, flags="PA", seq=attempt*1000+1, ack=5001+attempt)/Raw(load="SSH-2.0-OpenSSH\r\n")
        packets.append(ssh_data)
        
        # Connection reset
        rst = IP(src=target_ip, dst=attacker_ip)/TCP(sport=22, dport=sport, flags="R", seq=5001+attempt)
        packets.append(rst)
    
    # 3. HTTP with attacks
    print("  - HTTP attack patterns")
    
    # SQL injection attempt
    sql_payload = "GET /login.php?user=admin' OR '1'='1&password=x HTTP/1.1\r\nHost: vulnerable.local\r\nUser-Agent: sqlmap/1.0\r\n\r\n"
    sqli = IP(src="192.168.1.110", dst="192.168.1.30")/TCP(sport=54321, dport=80, flags="PA", seq=10000, ack=20000)/Raw(load=sql_payload)
    packets.append(sqli)
    
    # HTTP response
    response = IP(src="192.168.1.30", dst="192.168.1.110")/TCP(sport=80, dport=54321, flags="PA", seq=20000, ack=10000+len(sql_payload))/Raw(load="HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n<html>Login successful</html>")
    packets.append(response)
    
    # Directory traversal
    traversal_payload = "GET /../../../../etc/passwd HTTP/1.1\r\nHost: target.local\r\n\r\n"
    traversal = IP(src="192.168.1.111", dst="192.168.1.30")/TCP(sport=54322, dport=80, flags="PA", seq=30000, ack=40000)/Raw(load=traversal_payload)
    packets.append(traversal)
    
    # 4. DNS queries (including suspicious)
    print("  - DNS tunneling patterns")
    
    # Normal DNS
    dns_query = IP(src="192.168.1.50", dst="8.8.8.8")/UDP(sport=53001, dport=53)/DNS(qd=DNSQR(qname="google.com", qtype="A"))
    packets.append(dns_query)
    
    # DNS response
    dns_response = IP(src="8.8.8.8", dst="192.168.1.50")/UDP(sport=53, dport=53001)/DNS(qr=1, qd=DNSQR(qname="google.com"), an=DNSRR(rrname="google.com", rdata="142.250.80.46"))
    packets.append(dns_response)
    
    # Suspicious long DNS query (tunneling)
    long_domain = "data" + "x" * 50 + ".tunnel.evil.com"
    dns_tunnel = IP(src="192.168.1.102", dst="8.8.8.8")/UDP(sport=53002, dport=53)/DNS(qd=DNSQR(qname=long_domain))
    packets.append(dns_tunnel)
    
    # 5. C2 beacon traffic
    print("  - C2 beacon traffic")
    c2_ip = "185.159.158.1"
    infected = "192.168.1.105"
    
    for i in range(5):
        sport = random.randint(50000, 60000)
        # Beacon out
        beacon_data = f"BEACON:{i:04d}:ACTIVE:SYSINFO"
        beacon = IP(src=infected, dst=c2_ip)/TCP(sport=sport, dport=8443, flags="PA", seq=i*1000, ack=i*2000)/Raw(load=beacon_data)
        packets.append(beacon)
        
        # C2 response
        command = f"CMD:SLEEP:60"
        response = IP(src=c2_ip, dst=infected)/TCP(sport=8443, dport=sport, flags="PA", seq=i*2000, ack=i*1000+len(beacon_data))/Raw(load=command)
        packets.append(response)
    
    # Write PCAP
    wrpcap("/home/ubuntu/zeek_analysis/suspicious_traffic.pcap", packets)
    print(f"Generated suspicious_traffic.pcap with {len(packets)} packets")

def generate_normal_traffic():
    """Generate normal network traffic patterns"""
    packets = []
    
    print("Generating normal traffic patterns...")
    
    # Normal HTTP traffic
    print("  - Normal HTTP traffic")
    for i in range(5):
        src_ip = f"192.168.1.{50+i}"
        
        # HTTP GET request
        http_get = f"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 Firefox/91.0\r\nAccept: text/html\r\n\r\n"
        request = IP(src=src_ip, dst="192.168.1.80")/TCP(sport=random.randint(50000,60000), dport=80, flags="PA", seq=1000*i, ack=2000*i)/Raw(load=http_get)
        packets.append(request)
        
        # HTTP response
        http_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n<html><body>Welcome to Example.com</body></html>"
        response = IP(src="192.168.1.80", dst=src_ip)/TCP(sport=80, dport=request[TCP].sport, flags="PA", seq=2000*i, ack=1000*i+len(http_get))/Raw(load=http_resp)
        packets.append(response)
    
    # Normal DNS queries
    print("  - Normal DNS queries")
    domains = ["google.com", "github.com", "stackoverflow.com", "microsoft.com", "amazon.com"]
    for domain in domains:
        src_ip = "192.168.1.71"
        # Query
        dns_q = IP(src=src_ip, dst="192.168.1.1")/UDP(sport=random.randint(50000,60000), dport=53)/DNS(qd=DNSQR(qname=domain))
        packets.append(dns_q)
        
        # Response
        dns_r = IP(src="192.168.1.1", dst=src_ip)/UDP(sport=53, dport=dns_q[UDP].sport)/DNS(qr=1, qd=DNSQR(qname=domain), an=DNSRR(rrname=domain, rdata="93.184.216.34"))
        packets.append(dns_r)
    
    # Normal HTTPS (TLS handshake)
    print("  - HTTPS connections")
    for i in range(3):
        src_ip = f"192.168.1.{61+i}"
        sport = random.randint(50000, 60000)
        
        # TCP handshake
        syn = IP(src=src_ip, dst="192.168.1.443")/TCP(sport=sport, dport=443, flags="S", seq=1000)
        packets.append(syn)
        syn_ack = IP(src="192.168.1.443", dst=src_ip)/TCP(sport=443, dport=sport, flags="SA", seq=2000, ack=1001)
        packets.append(syn_ack)
        ack = IP(src=src_ip, dst="192.168.1.443")/TCP(sport=sport, dport=443, flags="A", seq=1001, ack=2001)
        packets.append(ack)
        
        # TLS Client Hello (simplified)
        tls_hello = b"\x16\x03\x01\x00\x50" + b"\x01" + b"\x00" * 79  # Simplified TLS
        tls_pkt = IP(src=src_ip, dst="192.168.1.443")/TCP(sport=sport, dport=443, flags="PA", seq=1001, ack=2001)/Raw(load=tls_hello)
        packets.append(tls_pkt)
    
    # Write PCAP
    wrpcap("/home/ubuntu/zeek_analysis/normal_traffic.pcap", packets)
    print(f"Generated normal_traffic.pcap with {len(packets)} packets")

def generate_malware_traffic():
    """Generate malware beacon traffic"""
    packets = []
    
    print("Generating malware beacon traffic...")
    
    c2_server = "45.142.120.5"
    infected_host = "192.168.1.150"
    
    # Initial connection
    sport = 55555
    syn = IP(src=infected_host, dst=c2_server)/TCP(sport=sport, dport=4444, flags="S", seq=1000)
    packets.append(syn)
    syn_ack = IP(src=c2_server, dst=infected_host)/TCP(sport=4444, dport=sport, flags="SA", seq=2000, ack=1001)
    packets.append(syn_ack)
    ack = IP(src=infected_host, dst=c2_server)/TCP(sport=sport, dport=4444, flags="A", seq=1001, ack=2001)
    packets.append(ack)
    
    # Regular beacons
    for i in range(10):
        # Beacon with system info
        beacon_data = f"BEACON:{i:04d}:HOST:WINBOX:USER:admin:STATUS:ACTIVE"
        beacon = IP(src=infected_host, dst=c2_server)/TCP(sport=sport, dport=4444, flags="PA", seq=1001+i*100, ack=2001+i*50)/Raw(load=beacon_data)
        packets.append(beacon)
        
        # C2 command
        if i % 3 == 0:
            cmd = "CMD:SCREENSHOT" if i == 3 else "CMD:KEYLOG:START" if i == 6 else "CMD:PERSIST"
            response = IP(src=c2_server, dst=infected_host)/TCP(sport=4444, dport=sport, flags="PA", seq=2001+i*50, ack=1001+i*100+len(beacon_data))/Raw(load=cmd)
            packets.append(response)
    
    # Write PCAP
    wrpcap("/home/ubuntu/zeek_analysis/sample_malware_conn.pcap", packets)
    print(f"Generated sample_malware_conn.pcap with {len(packets)} packets")

if __name__ == "__main__":
    print("Starting PCAP generation for Zeek analysis lab...")
    try:
        generate_suspicious_traffic()
        generate_normal_traffic()
        generate_malware_traffic()
        print("\nPCAP generation complete!")
        print("\nTesting with Zeek...")
        
        # Test the generated file
        import subprocess
        result = subprocess.run(["zeek", "-C", "-r", "/home/ubuntu/zeek_analysis/suspicious_traffic.pcap"], 
                              capture_output=True, text=True, cwd="/home/ubuntu/zeek_analysis")
        
        if result.returncode == 0:
            # Check if conn.log has content
            try:
                with open("/home/ubuntu/zeek_analysis/conn.log", "r") as f:
                    lines = len([l for l in f if not l.startswith("#")])
                    print(f"✓ Zeek successfully processed PCAP - conn.log has {lines} connections")
            except:
                print("✗ conn.log not found or empty")
        else:
            print("✗ Zeek processing failed")
            
    except Exception as e:
        print(f"Error: {e}")
        print("You may need to install scapy: pip3 install --user scapy")
