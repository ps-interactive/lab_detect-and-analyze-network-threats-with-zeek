##! Protocol anomaly detection script for Zeek
##! Detects protocol mismatches and missing required headers

module ProtocolAnomaly;

export {
    redef enum Notice::Type += {
        Protocol_Mismatch,
        Missing_Protocol_Headers,
        Suspicious_User_Agent,
        Long_DNS_Query
    };
    
    # DNS query length threshold
    const dns_length_threshold = 50 &redef;
}

# Check for HTTP on wrong ports
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {
    local resp_port = c$id$resp_p;
    
    # Check for plain HTTP on HTTPS port
    if (resp_port == 443/tcp) {
        NOTICE([$note=Protocol_Mismatch,
                $msg=fmt("Plain HTTP detected on HTTPS port 443 from %s", c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h, resp_port)]);
    }
}

# Check for suspicious DNS queries
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    # Check for unusually long DNS queries (potential DNS tunneling)
    if (|query| > dns_length_threshold) {
        NOTICE([$note=Long_DNS_Query,
                $msg=fmt("Unusually long DNS query (%d chars): %s from %s", 
                        |query|, query, c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, query)]);
    }
}
