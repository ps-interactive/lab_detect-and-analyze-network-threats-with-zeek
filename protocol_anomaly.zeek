##! Simple protocol anomaly detection script for Zeek

@load base/frameworks/notice

module ProtocolAnomaly;

export {
    redef enum Notice::Type += {
        Protocol_Anomaly,
        DNS_Anomaly
    };
}

# Check for HTTP anomalies (only if http.log exists)
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {
    
    # Check for SQL injection patterns
    if (/SELECT|UNION|OR.*=|'/ in original_URI) {
        NOTICE([$note=Protocol_Anomaly,
                $msg=fmt("SQL injection attempt detected from %s: %s", c$id$orig_h, original_URI),
                $conn=c,
                $identifier=cat(c$id$orig_h, "sqli")]);
    }
    
    # Check for directory traversal
    if (/\.\./ in original_URI) {
        NOTICE([$note=Protocol_Anomaly,
                $msg=fmt("Directory traversal attempt from %s: %s", c$id$orig_h, original_URI),
                $conn=c,
                $identifier=cat(c$id$orig_h, "traversal")]);
    }
}

# Check for DNS anomalies (only if dns.log exists)
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    # Check for unusually long DNS queries
    if (|query| > 50) {
        NOTICE([$note=DNS_Anomaly,
                $msg=fmt("Long DNS query detected from %s: %s (%d chars)", c$id$orig_h, query, |query|),
                $conn=c,
                $identifier=cat(c$id$orig_h, "long_dns")]);
    }
}
