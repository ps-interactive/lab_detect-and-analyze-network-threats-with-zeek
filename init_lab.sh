#!/bin/bash
echo "Zeek Lab Ready"
cd /home/ubuntu/zeek_analysis
ls -la *.pcap 2>/dev/null || echo "PCAPs will be generated"
