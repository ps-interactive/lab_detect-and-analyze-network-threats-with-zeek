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
if ls *.pcap 1> /dev/null 2>&1; then
    echo "✓ PCAP files found:"
    ls -lh *.pcap
else
    echo "✗ No PCAP files found. Creating sample files..."
    
    # Create sample PCAP files with tcpdump
    echo "Generating suspicious_traffic.pcap..."
    sudo timeout 10 tcpdump -i lo -w suspicious_traffic.pcap 2>/dev/null &
    TCPDUMP_PID=$!
    sleep 1
    
    # Generate some traffic
    ping -c 10 127.0.0.1 > /dev/null 2>&1 &
    nc -zv 127.0.0.1 22 80 443 2>/dev/null
    for port in 21 22 23 25 80 443; do
        timeout 0.1 nc -zv 127.0.0.1 $port 2>/dev/null
    done
    
    sleep 2
    sudo kill $TCPDUMP_PID 2>/dev/null
    wait $TCPDUMP_PID 2>/dev/null
    
    # Copy to create other files
    if [ -f suspicious_traffic.pcap ]; then
        cp suspicious_traffic.pcap normal_traffic.pcap
        cp suspicious_traffic.pcap sample_malware_conn.pcap
        echo "✓ Created PCAP files"
    else
        # Create minimal valid PCAP files
        for pcap in suspicious_traffic.pcap normal_traffic.pcap sample_malware_conn.pcap; do
            echo -ne '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' > $pcap
        done
        echo "✓ Created minimal PCAP files"
    fi
    
    # Set ownership
    sudo chown ubuntu:ubuntu *.pcap
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
