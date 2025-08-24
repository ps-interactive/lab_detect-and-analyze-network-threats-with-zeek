##! Detect protocol anomalies and mismatches

module ProtocolAnomaly;

export {
    redef enum Notice::Type += {
        Protocol_Mismatch,
        Missing_Protocol_Field,
        Suspicious_Protocol_Behavior
    };
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    # Check for missing Host header in HTTP/1.1
    if ( version == "1.1" && ! c$http?$host )
    {
        NOTICE([$note=Missing_Protocol_Field,
                $msg="HTTP/1.1 request missing Host header",
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_p)]);
    }
    
    # Check for missing User-Agent
    if ( ! c$http?$user_agent )
    {
        NOTICE([$note=Missing_Protocol_Field,
                $msg="HTTP request missing User-Agent header",
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_p)]);
    }
    
    # Check for HTTP on HTTPS port
    if ( c$id$resp_p == 443/tcp && c$service == "http" )
    {
        NOTICE([$note=Protocol_Mismatch,
                $msg="Plain HTTP detected on port 443 (HTTPS port)",
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_p)]);
    }
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    # Detect unusually long DNS queries (potential DNS tunneling)
    if ( |query| > 50 )
    {
        NOTICE([$note=Suspicious_Protocol_Behavior,
                $msg=fmt("Unusually long DNS query: %s (%d characters)", query, |query|),
                $conn=c,
                $identifier=cat(c$id$orig_h, query)]);
    }
}

event ssl_established(c: connection)
{
    # Check for SSL/TLS on non-standard ports
    if ( c$id$resp_p != 443/tcp && c$id$resp_p != 8443/tcp )
    {
        NOTICE([$note=Protocol_Mismatch,
                $msg=fmt("SSL/TLS on non-standard port %s", c$id$resp_p),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_p)]);
    }
}
