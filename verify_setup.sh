#!/bin/bash

# Verify Zeek lab setup
echo "Verifying Zeek lab environment setup..."
echo "======================================="

# Check if Zeek is installed
if command -v zeek &> /dev/null; then
    echo "✓ Zeek is installed: $(zeek --version 2>&1 | head -1)"
elif command -v bro &> /dev/null; then
    echo "✓ Bro (older Zeek) is installed: $(bro --version 2>&1 | head -1)"
else
    echo "✗ Zeek is not installed"
    exit 1
fi

# Check if zeek-cut is available
if command -v zeek-cut &> /dev/null; then
    echo "✓ zeek-cut is available"
else
    echo "✗ zeek-cut is not found"
fi

# Check Python and Scapy
if command -v python3 &> /dev/null; then
    echo "✓ Python3 is installed: $(python3 --version)"
    if python3 -c "import scapy" 2>/dev/null; then
        echo "✓ Scapy module is installed"
    else
        echo "⚠ Scapy module is not installed (needed for PCAP generation)"
    fi
else
    echo "✗ Python3 is not installed"
fi

# Check required directories
if [ -d "/home/ubuntu/zeek_analysis" ]; then
    echo "✓ Analysis directory exists"
else
    echo "⚠ Creating analysis directory..."
    mkdir -p /home/ubuntu/zeek_analysis
fi

if [ -d "/home/ubuntu/zeek_scripts" ]; then
    echo "✓ Scripts directory exists"
else
    echo "⚠ Creating scripts directory..."
    mkdir -p /home/ubuntu/zeek_scripts
fi

# Check if lab files are present
if [ -d "/home/ubuntu/lab" ]; then
    echo "✓ Lab repository is cloned"
    
    # Check for Zeek scripts
    for script in detect_scans.zeek protocol_anomaly.zeek correlation_rules.zeek; do
        if [ -f "/home/ubuntu/lab/$script" ]; then
            echo "  ✓ $script found"
        else
            echo "  ✗ $script missing"
        fi
    done
else
    echo "✗ Lab repository not found at /home/ubuntu/lab"
fi

echo ""
echo "Setup verification complete!"
echo "======================================="

# Run init_lab.sh if it exists
if [ -f "/home/ubuntu/lab/init_lab.sh" ]; then
    echo "Running lab initialization..."
    bash /home/ubuntu/lab/init_lab.sh
elif [ -f "/home/ubuntu/init_lab.sh" ]; then
    echo "Running lab initialization..."
    bash /home/ubuntu/init_lab.sh
else
    echo "⚠ init_lab.sh not found - PCAPs need to be generated"
fi
