#!/bin/bash
# Verify lab setup and fix common issues

echo "=== Zeek Lab Setup Verification ==="
echo

# Check for Zeek installation
echo "Checking for Zeek installation..."
if command -v zeek &> /dev/null; then
    echo "✓ Zeek found at: $(which zeek)"
    ZEEK_CMD="zeek"
elif command -v bro &> /dev/null; then
    echo "✓ Bro (legacy Zeek) found at: $(which bro)"
    ZEEK_CMD="bro"
    # Create zeek alias
    echo "Creating zeek alias for bro..."
    sudo ln -sf $(which bro) /usr/local/bin/zeek 2>/dev/null
else
    echo "✗ Zeek/Bro not found. Installing..."
    # Try to install zeek
    sudo apt update
    sudo apt install -y zeek-lts || sudo apt install -y bro || {
        echo "Failed to install from package manager."
        echo "Please install Zeek manually from: https://zeek.org/get-zeek/"
        exit 1
    }
fi

# Check for zeek-cut
echo
echo "Checking for zeek-cut..."
if command -v zeek-cut &> /dev/null; then
    echo "✓ zeek-cut found at: $(which zeek-cut)"
else
    echo "✗ zeek-cut not found. Creating alternative..."
    # Create simple zeek-cut alternative
    cat << 'EOF' | sudo tee /usr/local/bin/zeek-cut > /dev/null
#!/bin/bash
# Simple zeek-cut alternative
awk -F'\t' '
BEGIN {
    for (i = 1; i < ARGC; i++) {
        fields[ARGV[i]] = 1
        ARGV[i] = ""
    }
}
/^#fields/ {
    for (i = 2; i <= NF; i++) {
        if ($i in fields) {
            cols[++ncols] = i - 1
        }
    }
}
/^#/ { next }
{
    for (i = 1; i <= ncols; i++) {
        printf "%s", $cols[i]
        if (i < ncols) printf "\t"
    }
    printf "\n"
}' "$@"
EOF
    sudo chmod +x /usr/local/bin/zeek-cut
    echo "✓ Created zeek-cut alternative at /usr/local/bin/zeek-cut"
fi

# Check for PCAP files
echo
echo "Checking for PCAP files..."
cd /home/ubuntu/zeek_analysis 2>/dev/null || {
    echo "Creating zeek_analysis directory..."
    mkdir -p /home/ubuntu/zeek_analysis
    cd /home/ubuntu/zeek_analysis
}

for pcap in suspicious_traffic.pcap normal_traffic.pcap sample_malware_conn.pcap; do
    if [ -f "$pcap" ] && [ -s "$pcap" ]; then
        echo "✓ $pcap found ($(du -h $pcap | cut -f1))"
    else
        echo "✗ $pcap missing or empty"
        MISSING_PCAPS=1
    fi
done

# Generate PCAP files if missing
if [ "$MISSING_PCAPS" = "1" ]; then
    echo
    echo "Generating missing PCAP files..."
    
    # Try Python script first
    if [ -f /home/ubuntu/lab/generate_traffic.py ]; then
        sudo python3 /home/ubuntu/lab/generate_traffic.py 2>/dev/null && echo "✓ Generated PCAPs with Python script"
    fi
    
    # If still missing, create with tcpdump
    for pcap in suspicious_traffic.pcap normal_traffic.pcap sample_malware_conn.pcap; do
        if [ ! -s "$pcap" ]; then
            echo "Creating $pcap with tcpdump..."
            sudo timeout 5 tcpdump -i lo -w "$pcap" &
            PID=$!
            sleep 1
            # Generate some traffic
            ping -c 5 127.0.0.1 &>/dev/null
            nc -zv 127.0.0.1 22 80 443 &>/dev/null
            sleep 1
            sudo kill $PID 2>/dev/null
            wait $PID 2>/dev/null
            
            if [ -s "$pcap" ]; then
                echo "✓ Created $pcap"
            else
                # Create minimal valid PCAP
                echo -ne '\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00' > "$pcap"
                echo "✓ Created minimal $pcap"
            fi
        fi
    done
fi

# Check for Zeek scripts
echo
echo "Checking for Zeek scripts..."
cd /home/ubuntu/zeek_scripts 2>/dev/null || {
    echo "Creating zeek_scripts directory..."
    mkdir -p /home/ubuntu/zeek_scripts
    cd /home/ubuntu/zeek_scripts
}

for script in detect_scans.zeek protocol_anomaly.zeek correlation_rules.zeek; do
    if [ -f "$script" ] || [ -f "/home/ubuntu/lab/$script" ]; then
        [ -f "$script" ] || cp "/home/ubuntu/lab/$script" . 2>/dev/null
        echo "✓ $script found"
    else
        echo "✗ $script missing"
    fi
done

# Set permissions
echo
echo "Setting permissions..."
sudo chown -R ubuntu:ubuntu /home/ubuntu/zeek_analysis /home/ubuntu/zeek_scripts 2>/dev/null

# Test Zeek
echo
echo "Testing Zeek functionality..."
cd /home/ubuntu/zeek_analysis
if [ -s "suspicious_traffic.pcap" ]; then
    $ZEEK_CMD -r suspicious_traffic.pcap 2>/dev/null && {
        echo "✓ Zeek successfully processed test PCAP"
        if [ -f "conn.log" ]; then
            echo "✓ conn.log generated successfully"
        fi
    } || {
        echo "✗ Zeek processing failed"
    }
else
    echo "⚠ No PCAP file available for testing"
fi

echo
echo "=== Setup verification complete ==="
echo
echo "To start the lab, run:"
echo "  cd /home/ubuntu/zeek_analysis"
echo "  zeek -r suspicious_traffic.pcap"
echo
