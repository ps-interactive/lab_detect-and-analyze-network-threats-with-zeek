#!/usr/bin/env python3

import os
import time
import struct
import random
from datetime import datetime

# Generate network traffic patterns for analysis
def create_pcap_header():
    """Create PCAP file header"""
    magic_number = 0xa1b2c3d4
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    network = 1  # Ethernet
    
    return struct.pack('IHHiIII', magic_number, version_major, version_minor,
                      thiszone, sigfigs, snaplen, network)

def create_packet_header(length, timestamp):
    """Create PCAP packet header"""
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1000000)
    incl_len = length
    orig_len = length
    
    return struct.pack('IIII', ts_sec, ts_usec, incl_len, orig_len)

def create_tcp_syn_packet(src_ip, dst_ip, src_port, dst_port):
    """Create a TCP SYN packet"""
    # Ethernet header (14 bytes)
    eth_dst = b'\x00\x0c\x29\x00\x00\x01'
    eth_src = b'\x00\x0c\x29\x00\x00\x02'
    eth_type = b'\x08\x00'  # IPv4
    ethernet = eth_dst + eth_src + eth_type
    
    # IP header (20 bytes)
    version_ihl = b'\x45'
    tos = b'\x00'
    total_len = struct.pack('!H', 40)  # IP header + TCP header
    ip_id = struct.pack('!H', random.randint(1, 65535))
    flags_frag = b'\x40\x00'
    ttl = b'\x40'
    protocol = b'\x06'  # TCP
    checksum = b'\x00\x00'
    src_ip_bytes = struct.pack('!4B', *[int(x) for x in src_ip.split('.')])
    dst_ip_bytes = struct.pack('!4B', *[int(x) for x in dst_ip.split('.')])
    
    ip_header = version_ihl + tos + total_len + ip_id + flags_frag + \
                ttl + protocol + checksum + src_ip_bytes + dst_ip_bytes
    
    # TCP header (20 bytes)
    src_port_bytes = struct.pack('!H', src_port)
    dst_port_bytes = struct.pack('!H', dst_port)
    seq_num = struct.pack('!I', random.randint(0, 4294967295))
    ack_num = b'\x00\x00\x00\x00'
    data_offset = b'\x50'  # 5 * 4 = 20 bytes
    flags = b'\x02'  # SYN
    window = struct.pack('!H', 8192)
    tcp_checksum = b'\x00\x00'
    urgent = b'\x00\x00'
    
    tcp_header = src_port_bytes + dst_port_bytes + seq_num + ack_num + \
                 data_offset + flags + window + tcp_checksum + urgent
    
    return ethernet + ip_header + tcp_header

def create_http_request_packet(src_ip, dst_ip, uri, host=None):
    """Create an HTTP GET request packet"""
    # Build HTTP payload
    if "sql" in uri.lower() or "select" in uri.lower():
        # SQL injection attempt
        http_data = f"GET {uri} HTTP/1.1\r\n"
    elif ".." in uri:
        # Directory traversal attempt
        http_data = f"GET {uri} HTTP/1.1\r\n"
    else:
        http_data = f"GET {uri} HTTP/1.1\r\n"
    
    if host:
        http_data += f"Host: {host}\r\n"
    http_data += "User-Agent: Mozilla/5.0\r\n\r\n"
    
    # Ethernet header
    eth_dst = b'\x00\x0c\x29\x00\x00\x01'
    eth_src = b'\x00\x0c\x29\x00\x00\x02'
    eth_type = b'\x08\x00'
    ethernet = eth_dst + eth_src + eth_type
    
    # IP header
    version_ihl = b'\x45'
    tos = b'\x00'
    total_len = struct.pack('!H', 20 + 20 + len(http_data))
    ip_id = struct.pack('!H', random.randint(1, 65535))
    flags_frag = b'\x40\x00'
    ttl = b'\x40'
    protocol = b'\x06'
    checksum = b'\x00\x00'
    src_ip_bytes = struct.pack('!4B', *[int(x) for x in src_ip.split('.')])
    dst_ip_bytes = struct.pack('!4B', *[int(x) for x in dst_ip.split('.')])
    
    ip_header = version_ihl + tos + total_len + ip_id + flags_frag + \
                ttl + protocol + checksum + src_ip_bytes + dst_ip_bytes
    
    # TCP header with PSH+ACK flags
    src_port_bytes = struct.pack('!H', random.randint(1024, 65535))
    dst_port_bytes = struct.pack('!H', 80)
    seq_num = struct.pack('!I', random.randint(0, 4294967295))
    ack_num = struct.pack('!I', random.randint(0, 4294967295))
    data_offset = b'\x50'
    flags = b'\x18'  # PSH+ACK
    window = struct.pack('!H', 8192)
    tcp_checksum = b'\x00\x00'
    urgent = b'\x00\x00'
    
    tcp_header = src_port_bytes + dst_port_bytes + seq_num + ack_num + \
                 data_offset + flags + window + tcp_checksum + urgent
    
    return ethernet + ip_header + tcp_header + http_data.encode()

def create_dns_query_packet(src_ip, dst_ip, domain):
    """Create a DNS query packet"""
    # Ethernet header
    eth_dst = b'\x00\x0c\x29\x00\x00\x01'
    eth_src = b'\x00\x0c\x29\x00\x00\x02'
    eth_type = b'\x08\x00'
    ethernet = eth_dst + eth_src + eth_type
    
    # IP header
    version_ihl = b'\x45'
    tos = b'\x00'
    
    # DNS payload
    dns_id = struct.pack('!H', random.randint(1, 65535))
    dns_flags = b'\x01\x00'  # Standard query
    dns_qdcount = b'\x00\x01'  # 1 question
    dns_ancount = b'\x00\x00'
    dns_nscount = b'\x00\x00'
    dns_arcount = b'\x00\x00'
    
    # Encode domain name
    dns_question = b''
    for part in domain.split('.'):
        dns_question += bytes([len(part)]) + part.encode()
    dns_question += b'\x00'
    dns_question += b'\x00\x01'  # Type A
    dns_question += b'\x00\x01'  # Class IN
    
    dns_data = dns_id + dns_flags + dns_qdcount + dns_ancount + \
               dns_nscount + dns_arcount + dns_question
    
    total_len = struct.pack('!H', 20 + 8 + len(dns_data))  # IP + UDP + DNS
    ip_id = struct.pack('!H', random.randint(1, 65535))
    flags_frag = b'\x40\x00'
    ttl = b'\x40'
    protocol = b'\x11'  # UDP
    checksum = b'\x00\x00'
    src_ip_bytes = struct.pack('!4B', *[int(x) for x in src_ip.split('.')])
    dst_ip_bytes = struct.pack('!4B', *[int(x) for x in dst_ip.split('.')])
    
    ip_header = version_ihl + tos + total_len + ip_id + flags_frag + \
                ttl + protocol + checksum + src_ip_bytes + dst_ip_bytes
    
    # UDP header
    src_port = struct.pack('!H', random.randint(1024, 65535))
    dst_port = struct.pack('!H', 53)
    udp_len = struct.pack('!H', 8 + len(dns_data))
    udp_checksum = b'\x00\x00'
    
    udp_header = src_port + dst_port + udp_len + udp_checksum
    
    return ethernet + ip_header + udp_header + dns_data

def generate_suspicious_traffic():
    """Generate suspicious traffic PCAP"""
    print("Generating suspicious traffic patterns...")
    
    with open('suspicious_traffic.pcap', 'wb') as f:
        f.write(create_pcap_header())
        
        timestamp = time.time()
        
        # Port scanning pattern from 192.168.1.100
        scanner_ip = "192.168.1.100"
        target_ip = "192.168.1.10"
        
        for port in [21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 8080]:
            packet = create_tcp_syn_packet(scanner_ip, target_ip, 
                                          random.randint(1024, 65535), port)
            f.write(create_packet_header(len(packet), timestamp))
            f.write(packet)
            timestamp += 0.1
        
        # SSH brute force attempts from 203.0.113.50
        attacker_ip = "203.0.113.50"
        for _ in range(20):
            packet = create_tcp_syn_packet(attacker_ip, target_ip,
                                          random.randint(1024, 65535), 22)
            f.write(create_packet_header(len(packet), timestamp))
            f.write(packet)
            timestamp += 0.5
        
        # SQL injection attempts
        packet = create_http_request_packet("192.168.1.105", target_ip,
                                           "/login.php?user=admin' OR '1'='1", "test.com")
        f.write(create_packet_header(len(packet), timestamp))
        f.write(packet)
        timestamp += 1
        
        # Directory traversal attempts
        packet = create_http_request_packet("192.168.1.106", target_ip,
                                           "/../../../../etc/passwd", "test.com")
        f.write(create_packet_header(len(packet), timestamp))
        f.write(packet)
        timestamp += 1
        
        # DNS tunneling attempt (long domain)
        long_domain = "data" + "x" * 60 + ".evil.com"
        packet = create_dns_query_packet("192.168.1.107", "8.8.8.8", long_domain)
        f.write(create_packet_header(len(packet), timestamp))
        f.write(packet)
        timestamp += 1
        
        # Protocol mismatch - HTTP on port 443
        packet = create_http_request_packet("192.168.1.108", target_ip,
                                           "/", None)  # Missing host header
        f.write(create_packet_header(len(packet), timestamp))
        f.write(packet)

def generate_normal_traffic():
    """Generate normal traffic PCAP"""
    print("Generating normal traffic patterns...")
    
    with open('normal_traffic.pcap', 'wb') as f:
        f.write(create_pcap_header())
        
        timestamp = time.time()
        
        # Normal HTTP requests
        for _ in range(5):
            packet = create_http_request_packet("192.168.1.20", "192.168.1.10",
                                               "/index.html", "example.com")
            f.write(create_packet_header(len(packet), timestamp))
            f.write(packet)
            timestamp += random.uniform(1, 5)
        
        # Normal DNS queries
        for domain in ["google.com", "microsoft.com", "github.com"]:
            packet = create_dns_query_packet("192.168.1.21", "8.8.8.8", domain)
            f.write(create_packet_header(len(packet), timestamp))
            f.write(packet)
            timestamp += random.uniform(1, 3)

def generate_malware_beacon():
    """Generate C2 beacon traffic PCAP"""
    print("Generating malware beacon patterns...")
    
    with open('sample_malware_conn.pcap', 'wb') as f:
        f.write(create_pcap_header())
        
        timestamp = time.time()
        malware_ip = "192.168.1.150"
        c2_server = "10.0.0.100"
        
        # Regular beacon pattern - every 60 seconds
        for i in range(10):
            packet = create_tcp_syn_packet(malware_ip, c2_server,
                                          random.randint(1024, 65535), 4444)
            f.write(create_packet_header(len(packet), timestamp))
            f.write(packet)
            
            # Add some data transfer
            data_packet = create_http_request_packet(malware_ip, c2_server,
                                                    f"/beacon?id={i}", "c2.evil.com")
            f.write(create_packet_header(len(data_packet), timestamp + 0.1))
            f.write(data_packet)
            
            timestamp += 60  # Regular 60-second interval

if __name__ == "__main__":
    generate_suspicious_traffic()
    generate_normal_traffic()
    generate_malware_beacon()
    print("Traffic generation complete!")
