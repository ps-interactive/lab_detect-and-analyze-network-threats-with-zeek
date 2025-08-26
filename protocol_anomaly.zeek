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
    if (resp_port == 443/tcp && c$conn$conn_state != "SF") {
        NOTICE([$note=Protocol_Mismatch,
                $msg=fmt("Plain HTTP detected on HTTPS port 443 from %s", c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h, resp_port)]);
    }
    
    # Check for missing Host header in HTTP/1.1
    if (version == "1.1" && !c$http?$host) {
        NOTICE([$note=Missing_Protocol_Headers,
                $msg=fmt("HTTP/1.1 request missing Host header from %s", c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, "missing_host")]);
    }
    
    # Check for missing or suspicious User-Agent
    if (!c$http?$user_agent) {
        NOTICE([$note=Missing_Protocol_Headers,
                $msg=fmt("HTTP request missing User-Agent header from %s", c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, "missing_ua")]);
    } else if (c$http$user_agent == "-" || 
               c$http$user_agent == "" ||
               /^(curl|wget|python|ruby|perl)/i in c$http$user_agent) {
        NOTICE([$note=Suspicious_User_Agent,
                $msg=fmt("Suspicious User-Agent detected: %s from %s", 
                        c$http$user_agent, c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$http$user_agent)]);
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
    
    # Check for suspicious patterns in DNS queries
    if (/^[0-9a-f]{32,}/ in query ||  # Long hex strings
        /\.(tk|ml|ga|cf)$/ in query) { # Suspicious TLDs
        NOTICE([$note=Long_DNS_Query,
                $msg=fmt("Suspicious DNS query pattern: %s from %s", query, c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, query)]);
    }
}

# Detect weird protocol behaviors
event weird(name: string, msg: string, addl: string) {
    # Alert on specific weird behaviors that indicate attacks
    if (name == "truncated_header" || 
        name == "above_hole_data_without_any_acks" ||
        name == "bad_HTTP_request") {
        print fmt("Protocol anomaly detected: %s - %s", name, msg);
    }
}
