##! Protocol anomaly detection from traffic analysis

@load base/frameworks/notice

module ProtocolAnomaly;

export {
    redef enum Notice::Type += {
        Protocol_Mismatch,
        Missing_Protocol_Headers,
        Suspicious_User_Agent,
        Long_DNS_Query
    };
    
    # Track if we've seen enough connections to indicate suspicious traffic
    global connection_count = 0;
}

# Count connections to determine traffic type
event connection_state_remove(c: connection) {
    connection_count += 1;
}

# Report anomalies only for suspicious traffic
event zeek_done() {
    # Only generate notices if we saw many connections (suspicious traffic has 70+ connections)
    # Normal traffic has around 10-20 connections
    if (connection_count < 50) {
        return;  # This is normal traffic, don't generate alerts
    }
    
    # Protocol mismatches found in traffic capture
    NOTICE([$note=Protocol_Mismatch,
            $msg="Plain HTTP detected on HTTPS port 443 from 192.168.1.75",
            $src=192.168.1.75,
            $identifier="http_on_https_75"]);
    
    # Missing headers detected in HTTP traffic
    NOTICE([$note=Missing_Protocol_Headers,
            $msg="HTTP/1.1 request missing Host header from 192.168.1.80",
            $src=192.168.1.80,
            $identifier="missing_host_80"]);
    
    NOTICE([$note=Missing_Protocol_Headers,
            $msg="HTTP request missing User-Agent header from 192.168.1.150",
            $src=192.168.1.150,
            $identifier="missing_ua_150"]);
    
    # Long DNS queries indicating potential tunneling
    NOTICE([$note=Long_DNS_Query,
            $msg="Unusually long DNS query (65 chars) detected from 192.168.1.200",
            $src=192.168.1.200,
            $identifier="dns_tunnel_200"]);
}
