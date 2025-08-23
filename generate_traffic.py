#!/usr/bin/env python3
"""
Generate sample network traffic PCAP files for Zeek analysis lab
This version uses system tools instead of Scapy for better compatibility
"""

import subprocess
import time
import threading
import os

def run_tcpdump(filename, duration=10):
    """Run tcpdump to capture traffic"""
    cmd = f"sudo tcpdump -i lo -w {filename}"
    proc = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(duration)
    proc.terminate()
    proc.wait()
    return filename

def generate_port_scan():
    """Generate port scanning traffic"""
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]
    for port in ports:
        subprocess.run(f"nc -zv -w1 127.0.0.1 {port}".split(), 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.05)

def generate_ssh_brute_force():
    """Generate SSH brute force attempts"""
    for i in range(30):
        subprocess.run("nc -w1 127.0.0.1 22".split(), 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.1)

def generate_http_attacks():
    """Generate HTTP attack patterns"""
    attacks = [
        "curl -s http://127.0.0.1:8080/login.php?user=admin'+OR+'1'='1",
        "curl -s http://127.0.0.1:8080/../../../../etc/passwd",
        "curl -s http://127.0.0.1:8080/admin/config.php",
        "curl -s http://127.0.0.1:8080/phpmyadmin",
    ]
    for attack in attacks:
        subprocess.run(attack.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.2)

def generate_normal_traffic():
    """Generate normal network traffic"""
    # Normal HTTP requests
    urls = [
        "http://127.0.0.1:8080/index.html",
        "http://127.0.0.1:8080/about.html",
        "http://127.0.0.1:8080/contact.html",
    ]
    for url in urls:
        subprocess.run(f"curl -s {url}".split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
    
    # Normal DNS queries
    domains = ["google.com", "github.com", "stackoverflow.com", "microsoft.com"]
    for domain in domains:
        subprocess.run(f"nslookup {domain} 127.0.0.1".split(), 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.3)

def generate_beacon_traffic():
    """Generate C2 beacon traffic"""
    for i in range(10):
        cmd = f"echo BEACON:{i}:ACTIVE | nc -w1 127.0.0.1 4444"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)  # Regular interval for beacon

def main():
    """Main function to generate all PCAP files"""
    os.chdir("/home/ubuntu/zeek_analysis")
    
    # Start a simple HTTP server for traffic generation
    http_server = subprocess.Popen(["python3", "-m", "http.server", "8080"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    
    try:
        # Generate suspicious traffic
        print("Generating suspicious_traffic.pcap...")
        tcpdump_thread = threading.Thread(target=run_tcpdump, 
                                         args=("suspicious_traffic.pcap", 15))
        tcpdump_thread.start()
        time.sleep(1)
        
        generate_port_scan()
        generate_ssh_brute_force()
        generate_http_attacks()
        
        tcpdump_thread.join()
        
        # Generate normal traffic
        print("Generating normal_traffic.pcap...")
        tcpdump_thread = threading.Thread(target=run_tcpdump, 
                                         args=("normal_traffic.pcap", 10))
        tcpdump_thread.start()
        time.sleep(1)
        
        generate_normal_traffic()
        
        tcpdump_thread.join()
        
        # Generate malware traffic
        print("Generating sample_malware_conn.pcap...")
        tcpdump_thread = threading.Thread(target=run_tcpdump, 
                                         args=("sample_malware_conn.pcap", 12))
        tcpdump_thread.start()
        time.sleep(1)
        
        generate_beacon_traffic()
        
        tcpdump_thread.join()
        
    finally:
        # Clean up
        http_server.terminate()
        http_server.wait()
    
    # Set proper permissions
    subprocess.run("sudo chown ubuntu:ubuntu *.pcap", shell=True)
    subprocess.run("sudo chmod 644 *.pcap", shell=True)
    
    print("PCAP generation complete!")
    subprocess.run("ls -lh *.pcap", shell=True)

if __name__ == "__main__":
    main()
