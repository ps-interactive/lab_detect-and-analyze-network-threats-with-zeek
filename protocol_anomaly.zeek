##! Detect protocol anomalies and mismatches
##! This script identifies when protocols don't match expected ports

@load base/frameworks/notice
@load base/protocols/http
@load base/protocols/ssl

module ProtocolAnomaly;

export {
    redef enum Notice::Type += {
        ## Protocol mismatch detected
        Protocol_Mismatch,
        ## Missing required protocol fields
        Missing_Protocol_Fields,
        ## Suspicious protocol behavior
        Suspicious_Protocol_Behavior
    };
}

# Check for HTTP traffic on non-standard ports
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    local dport = c$id$resp_p;
    
    # Alert on HTTP on HTTPS port
    if ( dport == 443/tcp )
    {
        NOTICE([$note=Protocol_Mismatch,
                $msg=fmt("Plain HTTP detected on HTTPS port 443 from %s", c$id$orig_h),
                $conn=c,
                $identifier=cat(c$uid)]);
    }
    
    # Alert on HTTP on unusual ports
    if ( dport != 80/tcp && dport != 8080/tcp && dport != 8000/tcp )
    {
        NOTICE([$note=Suspicious_Protocol_Behavior,
                $msg=fmt("HTTP traffic on unusual port %s from %s", dport, c$id$orig_h),
                $conn=c,
                $identifier=cat(c$uid)]);
    }
}

# Check for missing HTTP headers
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    # Track if Host header exists
    if ( is_orig && name == "HOST" )
        c$http$host = value;
}

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{
    if ( is_orig )
    {
        local has_host = F;
        local has_user_agent = F;
        
        for ( i in hlist )
        {
            if ( hlist[i]$name == "HOST" )
                has_host = T;
            if ( hlist[i]$name == "USER-AGENT" )
                has_user_agent = T;
        }
        
        # HTTP/1.1 requires Host header
        if ( ! has_host && c$http?$version && c$http$version == "1.1" )
        {
            NOTICE([$note=Missing_Protocol_Fields,
                    $msg=fmt("HTTP/1.1 request missing Host header from %s", c$id$orig_h),
                    $conn=c,
                    $identifier=cat(c$uid)]);
        }
        
        # Suspicious if no User-Agent
        if ( ! has_user_agent )
        {
            NOTICE([$note=Suspicious_Protocol_Behavior,
                    $msg=fmt("HTTP request missing User-Agent from %s", c$id$orig_h),
                    $conn=c,
                    $identifier=cat(c$uid)]);
        }
    }
}

# Detect SSL/TLS on non-standard ports
event ssl_established(c: connection)
{
    local dport = c$id$resp_p;
    
    if ( dport != 443/tcp && dport != 8443/tcp && dport != 465/tcp && 
         dport != 993/tcp && dport != 995/tcp )
    {
        NOTICE([$note=Suspicious_Protocol_Behavior,
                $msg=fmt("SSL/TLS on unusual port %s from %s", dport, c$id$orig_h),
                $conn=c,
                $identifier=cat(c$uid)]);
    }
}

# Detect unusually long DNS queries (potential DNS tunneling)
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if ( |query| > 100 )
    {
        NOTICE([$note=Suspicious_Protocol_Behavior,
                $msg=fmt("Unusually long DNS query (%d bytes) from %s: %s", 
                        |query|, c$id$orig_h, query),
                $conn=c,
                $identifier=cat(c$uid)]);
    }
    
    # Check for excessive subdomains (another tunneling indicator)
    local subdomain_count = 0;
    for ( i in query )
    {
        if ( query[i] == "." )
            subdomain_count += 1;
    }
    
    if ( subdomain_count > 5 )
    {
        NOTICE([$note=Suspicious_Protocol_Behavior,
                $msg=fmt("DNS query with %d subdomains from %s", 
                        subdomain_count, c$id$orig_h),
                $conn=c,
                $identifier=cat(c$uid)]);
    }
}
