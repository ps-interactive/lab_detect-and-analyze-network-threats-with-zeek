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
    echo "✗ Missing or invalid PCAP files. Creating all three with real traffic..."
    
    # Start a background service to generate traffic
    sudo python3 -m http.server 8080 >/dev/null 2>&1 &
    HTTP_PID=$!
    
    # Generate suspicious_traffic.pcap with actual packets
    echo "Generating suspicious_traffic.pcap with real packets..."
    sudo tcpdump -i any -w suspicious_traffic_tmp.pcap 'not port 22' >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
    
    # Generate various traffic patterns
    # Port scanning
    echo "  Simulating port scan..."
    for port in 21 23 25 80 110 143 443 445 1433 3306 3389 8080; do
        timeout 0.1 nc -zv 127.0.0.1 $port 2>/dev/null &
    done
    
    # HTTP requests
    echo "  Generating HTTP traffic..."
    curl -s http://127.0.0.1:8080/ >/dev/null 2>&1 &
    wget -q -O /dev/null http://127.0.0.1:8080/index.html 2>/dev/null &
    
    # DNS queries
    echo "  Generating DNS queries..."
    for i in {1..10}; do
        nslookup example$i.com 8.8.8.8 2>/dev/null &
        host test$i.local 2>/dev/null &
    done
    
    # SSH attempts
    echo "  Simulating SSH connections..."
    for i in {1..20}; do
        timeout 0.1 ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no user$i@127.0.0.1 2>/dev/null &
    done
    
    # Generate pings
    ping -c 50 127.0.0.1 >/dev/null 2>&1 &
    ping -c 50 8.8.8.8 >/dev/null 2>&1 &
    
    sleep 5
    sudo kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null
    
    # Move and set permissions
    sudo mv suspicious_traffic_tmp.pcap suspicious_traffic.pcap 2>/dev/null
    sudo chown ubuntu:ubuntu suspicious_traffic.pcap
    
    # Generate normal_traffic.pcap
    echo "Generating normal_traffic.pcap with real packets..."
    sudo tcpdump -i any -w normal_traffic_tmp.pcap 'not port 22' >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
    
    # Normal web traffic
    echo "  Generating normal web traffic..."
    curl -s http://127.0.0.1:8080/ >/dev/null 2>&1
    curl -s http://127.0.0.1:8080/test >/dev/null 2>&1
    
    # Normal DNS
    echo "  Normal DNS lookups..."
    for domain in google.com github.com ubuntu.com microsoft.com; do
        nslookup $domain 2>/dev/null
    done
    
    # Some pings
    ping -c 20 127.0.0.1 >/dev/null 2>&1 &
    
    sleep 3
    sudo kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null
    
    sudo mv normal_traffic_tmp.pcap normal_traffic.pcap 2>/dev/null
    sudo chown ubuntu:ubuntu normal_traffic.pcap
    
    # Generate sample_malware_conn.pcap
    echo "Generating sample_malware_conn.pcap with beacon pattern..."
    sudo tcpdump -i any -w sample_malware_conn_tmp.pcap 'not port 22' >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1
    
    # Simulate C2 beacons
    echo "  Simulating C2 beacon traffic..."
    for i in {1..10}; do
        echo "BEACON:$i:ACTIVE" | nc -w1 127.0.0.1 4444 2>/dev/null
        curl -s http://127.0.0.1:8080/beacon$i >/dev/null 2>&1
        sleep 0.5
    done
    
    # More traffic
    ping -c 10 127.0.0.1 >/dev/null 2>&1
    
    sleep 2
    sudo kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null
    
    sudo mv sample_malware_conn_tmp.pcap sample_malware_conn.pcap 2>/dev/null
    sudo chown ubuntu:ubuntu sample_malware_conn.pcap
    
    # Kill the HTTP server
    sudo kill $HTTP_PID 2>/dev/null
    
    # Verify all files exist and have content
    echo
    echo "Verifying PCAP files..."
    for pcap in suspicious_traffic.pcap normal_traffic.pcap sample_malware_conn.pcap; do
        if [ -f "$pcap" ]; then
            SIZE=$(stat -c%s "$pcap")
            if [ "$SIZE" -gt "1000" ]; then
                echo "✓ $pcap: $(ls -lh $pcap | awk '{print $5}')"
            else
                echo "✗ $pcap is too small ($SIZE bytes)"
                # As last resort, download a sample PCAP
                echo "  Attempting to download sample PCAP..."
                curl -s -o "$pcap" "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http.cap" 2>/dev/null || \
                wget -q -O "$pcap" "https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/http.cap" 2>/dev/null || \
                echo "  Download failed"
            fi
        else
            echo "✗ $pcap not found"
        fi
    done
    
    # Set final permissions
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
    echo "  You are likely on the Console version. Please use Ubuntu Desktop instead."
    ZEEK_CMD="echo 'Zeek not installed'"
fi

# Check for zeek-cut
echo
echo "Checking for zeek-cut..."
if command -v zeek-cut &> /dev/null; then
    echo "✓ zeek-cut is available"
else
    echo "✗ zeek-cut not found. Creating alternative..."
    cat << 'EOF' > ~/zeek-cut
#!/bin/bash
awk -F'\t' '/^#fields/{for(i=2;i<=NF;i++)f[$i]=i-1}/^#/{next}{for(i=1;i<ARGC;i++)if(ARGV[i] in f){printf "%s",$f[ARGV[i]];if(i<ARGC-1)printf "\t"}printf "\n"}' "$@"
EOF
    chmod +x ~/zeek-cut
    export PATH=$PATH:~
    echo "✓ Created zeek-cut alternative"
fi

# Copy Zeek scripts if they exist
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

# Test Zeek with proper permissions
echo
echo "Testing Zeek..."
if [ -f suspicious_traffic.pcap ]; then
    # Run zeek without trying to write to current directory
    $ZEEK_CMD -r suspicious_traffic.pcap local "Log::default_logdir=/tmp/zeek_test" 2>/dev/null && {
        echo "✓ Zeek processed test PCAP successfully"
        echo "  Note: Logs written to /tmp/zeek_test/"
        # Copy logs back if they exist
        if [ -d /tmp/zeek_test ]; then
            cp /tmp/zeek_test/*.log . 2>/dev/null
            echo "  Logs copied to current directory"
        fi
    } || {
        echo "⚠ Zeek processing had issues. Try running with sudo or in /tmp"
    }
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
echo "If you get permission errors, try:"
echo "  sudo $ZEEK_CMD -r suspicious_traffic.pcap"
echo "  OR"
echo "  cd /tmp && $ZEEK_CMD -r ~/zeek_analysis/suspicious_traffic.pcap"
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
