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
    
    # Ensure we have required tools
    which nc >/dev/null 2>&1 || sudo apt-get install -y netcat-openbsd >/dev/null 2>&1
    which curl >/dev/null 2>&1 || sudo apt-get install -y curl >/dev/null 2>&1
    
    # Clean up old files
    rm -f suspicious_traffic.pcap normal_traffic.pcap sample_malware_conn.pcap 2>/dev/null
    
    # Create suspicious traffic with HTTP support
    echo "  Creating port scan traffic..."
    
    # Start a simple HTTP server for real HTTP traffic
    python3 -m http.server 8080 >/dev/null 2>&1 &
    HTTP_SERVER_PID=$!
    sleep 2
    
    # Start packet capture for suspicious traffic
    sudo timeout 25 tcpdump -i lo -w suspicious_traffic.pcap >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 2
    
    # Generate port scanning pattern locally
    for port in 21 22 23 25 53 80 110 143 443 445 1433 3306 3389 8080; do
        (timeout 0.1 nc -zv 127.0.0.1 $port 2>/dev/null || true) &
    done
    
    # SSH brute force simulation
    echo "  Creating SSH brute force attempts..."
    for i in {1..20}; do
        (echo "SSH-2.0-Test" | timeout 0.1 nc 127.0.0.1 22 2>/dev/null || true) &
    done
    
    # HTTP with SQL injection using curl
    echo "  Creating HTTP attack patterns..."
    curl -s "http://127.0.0.1:8080/login.php?user=admin'+OR+'1'='1" >/dev/null 2>&1 || true
    curl -s "http://127.0.0.1:8080/../../../../etc/passwd" >/dev/null 2>&1 || true
    curl -s "http://127.0.0.1:8080/admin.php" -H "User-Agent: " >/dev/null 2>&1 || true
    curl -s "http://127.0.0.1:8080/test" >/dev/null 2>&1 || true
    
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
    kill $HTTP_SERVER_PID 2>/dev/null
    
    # Create normal traffic
    echo "  Creating normal web traffic..."
    
    # Start HTTP server again
    python3 -m http.server 8080 >/dev/null 2>&1 &
    HTTP_SERVER_PID=$!
    sleep 2
    
    sudo timeout 15 tcpdump -i lo -w normal_traffic.pcap >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 2
    
    # Normal HTTP traffic
    for i in {1..10}; do
        curl -s "http://127.0.0.1:8080/index.html" -H "User-Agent: Mozilla/5.0" >/dev/null 2>&1 || true
    done
    
    # Normal DNS
    for domain in google.com github.com stackoverflow.com; do
        (nslookup $domain 127.0.0.1 2>/dev/null || true) &
    done
    
    sleep 3
    sudo kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null
    kill $HTTP_SERVER_PID 2>/dev/null
    
    # Create C2 beacon traffic
    echo "  Creating C2 beacon traffic..."
    sudo timeout 15 tcpdump -i lo -w sample_malware_conn.pcap >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 2
    
    # Regular beacon pattern
    for i in {1..10}; do
        (echo "BEACON:$(printf '%04d' $i):STATUS" | timeout 0.2 nc 127.0.0.1 4444 2>/dev/null || true) &
        sleep 0.5
    done
    
    sleep 3
    sudo kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null
    
    # Ensure minimum valid PCAP files
    for pcap in suspicious_traffic.pcap normal_traffic.pcap sample_malware_conn.pcap; do
        if [ ! -f "$pcap" ] || [ ! -s "$pcap" ]; then
            echo "  Warning: $pcap missing or empty, creating minimal valid file..."
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
