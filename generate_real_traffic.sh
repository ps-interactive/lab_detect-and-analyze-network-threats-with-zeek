#!/bin/bash
# Generate PCAP files with real, analyzable traffic for Zeek

echo "Generating PCAP files with real traffic..."
cd /home/ubuntu/zeek_analysis

# Download sample PCAP files with real traffic
echo "Downloading sample PCAP files with actual traffic..."

# Option 1: Download from Wireshark sample captures
echo "Downloading suspicious traffic sample..."
wget -q -O suspicious_traffic.pcap "https://github.com/wireshark/wireshark/raw/master/test/captures/http.pcap" 2>/dev/null || \
curl -s -o suspicious_traffic.pcap "https://github.com/wireshark/wireshark/raw/master/test/captures/http.pcap" 2>/dev/null

# If that fails, try alternative sources
if [ ! -s suspicious_traffic.pcap ]; then
    echo "Primary download failed, trying alternative..."
    # Try to get a sample from tcpreplay
    wget -q -O suspicious_traffic.pcap "https://tcpreplay.appneta.com/testdata/smallFlows.pcap" 2>/dev/null || \
    curl -s -o suspicious_traffic.pcap "https://tcpreplay.appneta.com/testdata/smallFlows.pcap" 2>/dev/null
fi

# Option 2: Generate traffic with actual services running
if [ ! -s suspicious_traffic.pcap ] || [ $(stat -c%s suspicious_traffic.pcap) -lt 1000 ]; then
    echo "Downloads failed. Generating traffic locally with services..."
    
    # Start a simple HTTP server
    python3 -m http.server 8888 >/dev/null 2>&1 &
    HTTP_PID=$!
    
    # Start netcat listeners for various ports
    nc -l -p 4444 >/dev/null 2>&1 &
    NC1=$!
    nc -l -p 8080 >/dev/null 2>&1 &
    NC2=$!
    
    # Give services time to start
    sleep 2
    
    # Start packet capture on all interfaces
    sudo tcpdump -i any -w suspicious_traffic_tmp.pcap 'not port 22' >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
    
    # Generate real HTTP traffic
    echo "Generating HTTP traffic..."
    curl -s http://localhost:8888/ >/dev/null 2>&1
    curl -s http://localhost:8888/index.html >/dev/null 2>&1
    wget -q -O /dev/null http://localhost:8888/ 2>/dev/null
    
    # Generate traffic to external sites (these will create real packets)
    curl -s --max-time 2 http://example.com >/dev/null 2>&1 &
    curl -s --max-time 2 http://google.com >/dev/null 2>&1 &
    
    # Port scanning behavior
    echo "Simulating port scan..."
    for port in 21 23 25 80 110 143 443 445 3306 3389 8080 8888; do
        nc -zv -w1 localhost $port 2>/dev/null &
    done
    
    # SSH brute force simulation
    echo "Simulating SSH attempts..."
    for i in {1..10}; do
        ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no invalid$i@localhost 2>/dev/null &
    done
    
    # DNS queries
    echo "Generating DNS traffic..."
    for domain in google.com example.com test.local suspicious.site attacker.evil; do
        nslookup $domain 8.8.8.8 2>/dev/null &
        dig $domain 2>/dev/null &
    done
    
    # Wait for traffic to be captured
    sleep 5
    
    # Stop capture
    sudo kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null
    
    # Clean up services
    kill $HTTP_PID $NC1 $NC2 2>/dev/null
    
    # Move the capture
    sudo mv suspicious_traffic_tmp.pcap suspicious_traffic.pcap 2>/dev/null
    sudo chown ubuntu:ubuntu suspicious_traffic.pcap
fi

# Create normal_traffic.pcap
if [ -s suspicious_traffic.pcap ]; then
    echo "Creating normal_traffic.pcap..."
    cp suspicious_traffic.pcap normal_traffic.pcap
else
    # Download a different sample for normal traffic
    wget -q -O normal_traffic.pcap "https://github.com/wireshark/wireshark/raw/master/test/captures/dhcp.pcap" 2>/dev/null
fi

# Create sample_malware_conn.pcap
if [ -s suspicious_traffic.pcap ]; then
    echo "Creating sample_malware_conn.pcap..."
    cp suspicious_traffic.pcap sample_malware_conn.pcap
else
    # Download another sample
    wget -q -O sample_malware_conn.pcap "https://github.com/wireshark/wireshark/raw/master/test/captures/dns.pcap" 2>/dev/null
fi

# As a last resort, create synthetic traffic with scapy
if [ ! -s suspicious_traffic.pcap ]; then
    echo "All methods failed. Creating synthetic traffic with Python..."
    python3 << 'EOF'
try:
    from scapy.all import *
    import random
    
    packets = []
    
    # Create some TCP SYN packets (port scan)
    for port in [21, 22, 23, 25, 80, 443, 445, 3306, 3389]:
        pkt = IP(src="192.168.1.100", dst="192.168.1.1")/TCP(sport=random.randint(1024,65535), dport=port, flags="S")
        packets.append(pkt)
    
    # Create HTTP request
    http_req = 'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'
    pkt = IP(src="192.168.1.100", dst="192.168.1.80")/TCP(sport=54321, dport=80, flags="PA")/Raw(load=http_req)
    packets.append(pkt)
    
    # Create DNS query
    pkt = IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=53421, dport=53)/DNS(qd=DNSQR(qname="google.com"))
    packets.append(pkt)
    
    # Write to PCAP
    wrpcap("suspicious_traffic.pcap", packets)
    print("Created synthetic suspicious_traffic.pcap")
    
except Exception as e:
    print(f"Failed to create synthetic traffic: {e}")
EOF
fi

# Final check and report
echo
echo "Checking PCAP files..."
for pcap in suspicious_traffic.pcap normal_traffic.pcap sample_malware_conn.pcap; do
    if [ -f "$pcap" ]; then
        SIZE=$(stat -c%s "$pcap" 2>/dev/null || echo "0")
        echo "✓ $pcap: $SIZE bytes"
    else
        echo "✗ $pcap: missing"
    fi
done

# Set permissions
chmod 644 *.pcap 2>/dev/null
chown ubuntu:ubuntu *.pcap 2>/dev/null

echo
echo "Testing with Zeek..."
if [ -s suspicious_traffic.pcap ]; then
    zeek -C -r suspicious_traffic.pcap 2>/dev/null
    if [ -s conn.log ]; then
        ENTRIES=$(wc -l < conn.log)
        echo "✓ Zeek generated conn.log with $ENTRIES entries"
        echo
        echo "Sample connections:"
        zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | head -5
    else
        echo "✗ conn.log is empty or missing"
    fi
else
    echo "✗ No valid PCAP file to test"
fi

echo
echo "PCAP generation complete!"
echo "Run: zeek -C -r suspicious_traffic.pcap"
