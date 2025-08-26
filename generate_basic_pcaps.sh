#!/bin/bash
# Fallback script to generate basic PCAP files using tcpdump and nc

# Function to generate basic traffic
generate_basic_traffic() {
    echo "Generating basic traffic patterns..."
    
    # Start tcpdump in background
    sudo tcpdump -i lo -w /tmp/capture.pcap &
    TCPDUMP_PID=$!
    sleep 2
    
    # Generate some basic traffic patterns
    
    # Port scan simulation
    for port in 21 22 23 25 80 443 445 3306 3389 8080; do
        timeout 0.1 nc -zv 127.0.0.1 $port 2>/dev/null || true
    done
    
    # HTTP traffic
    echo -e "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" | nc -w1 127.0.0.1 80 2>/dev/null || true
    echo -e "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n" | nc -w1 127.0.0.1 80 2>/dev/null || true
    
    # SSH attempts
    for i in {1..10}; do
        timeout 0.1 nc -w1 127.0.0.1 22 2>/dev/null || true
    done
    
    # DNS queries
    for domain in google.com facebook.com attacker.evil longsubdomain.tunnel.suspicious.com; do
        nslookup $domain 127.0.0.1 2>/dev/null || true
    done
    
    sleep 2
    sudo kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null
    
    # Copy and rename files
    sudo cp /tmp/capture.pcap /home/ubuntu/zeek_analysis/suspicious_traffic.pcap
    sudo cp /tmp/capture.pcap /home/ubuntu/zeek_analysis/normal_traffic.pcap
    sudo cp /tmp/capture.pcap /home/ubuntu/zeek_analysis/sample_malware_conn.pcap
    
    # Set permissions
    sudo chown ubuntu:ubuntu /home/ubuntu/zeek_analysis/*.pcap
    
    echo "Basic PCAP files generated"
}

# Run if executed directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    generate_basic_traffic
fi
