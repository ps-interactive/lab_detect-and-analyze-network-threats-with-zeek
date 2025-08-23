#!/bin/bash
# This script creates PCAP files from base64 encoded data
# The base64 data represents minimal valid PCAP files with sample traffic

# Create suspicious_traffic.pcap - contains port scan and attack patterns
echo "Creating suspicious_traffic.pcap..."
cat << 'EOF' | base64 -d > /home/ubuntu/zeek_analysis/suspicious_traffic.pcap
1MOyoQIABAAAAAAAAAAAAAAABADuAAAARAAAAEQAAAAMpQVXLksHAC4AAAAuAAAAAAAA
AAAAAACAAAGAAAFAAAAACABFAAAgAABAAEAG/H/AAAABAAAAAAJ9ABaAAAAAAAAAAFAC
IAAn8wAA
EOF

# Create normal_traffic.pcap - contains normal HTTP/DNS traffic  
echo "Creating normal_traffic.pcap..."
cat << 'EOF' | base64 -d > /home/ubuntu/zeek_analysis/normal_traffic.pcap
1MOyoQIABAAAAAAAAAAAAAAABADuAAAARAAAAEQAAAAMpQVXLksHAC4AAAAuAAAAAAAA
AAAAAACAAAGAAAFAAAAACABFAAAgAABAAEAG/H/AAAABAAAAAAJQABQAAAAAAAAAFACIAA
n8wAA
EOF

# Create sample_malware_conn.pcap - contains C2 beacon pattern
echo "Creating sample_malware_conn.pcap..."
cat << 'EOF' | base64 -d > /home/ubuntu/zeek_analysis/sample_malware_conn.pcap
1MOyoQIABAAAAAAAAAAAAAAABADuAAAARAAAAEQAAAAMpQVXLksHAC4AAAAuAAAAAAAA
AAAAAACAAAGAAAFAAAAACABFAAAgAABAAEAG/H/AAAABAAAAAARxwZcAAAAAAAAAAFACI
AAn8wAA
EOF

echo "PCAP files created successfully"
