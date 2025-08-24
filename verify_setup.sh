#!/bin/bash

echo "Verifying Zeek lab setup..."

# Check if Zeek is installed
if command -v zeek &> /dev/null; then
    echo "✓ Zeek is installed: $(zeek --version 2>&1 | head -n1)"
else
    echo "✗ Zeek is not installed"
fi

# Check if zeek-cut is available
if command -v zeek-cut &> /dev/null; then
    echo "✓ zeek-cut is available"
else
    echo "✗ zeek-cut is not available"
fi

# Check if Python3 is installed
if command -v python3 &> /dev/null; then
    echo "✓ Python3 is installed: $(python3 --version)"
else
    echo "✗ Python3 is not installed"
fi

# Check if scapy is installed
if python3 -c "import scapy" 2>/dev/null; then
    echo "✓ Python scapy module is installed"
else
    echo "✗ Python scapy module is not installed"
fi

# Check if required directories exist
for dir in /home/ubuntu/zeek_analysis /home/ubuntu/zeek_scripts; do
    if [ -d "$dir" ]; then
        echo "✓ Directory exists: $dir"
    else
        echo "✗ Directory missing: $dir"
    fi
done

echo "Setup verification complete!"
