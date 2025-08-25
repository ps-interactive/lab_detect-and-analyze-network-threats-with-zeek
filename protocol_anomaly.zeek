##! Detect protocol anomalies and mismatches

module ProtocolAnomaly;

export {
    redef enum Notice::Type += {
        Protocol_Mismatch,
        Missing_HTTP_Header,
        SQL_Injection_Attempt,
        Directory_Traversal_Attempt,
        DNS_Tunneling_Suspected
    };
}

# Detect HTTP on non-HTTP ports
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    if ( c$id$resp_p == 443/tcp )
        {
        NOTICE([$note=Protocol_Mismatch,
                $msg=fmt("Plain HTTP traffic on HTTPS port 443 from %s", c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h, c$id$resp_p)]);
        }
    
    # Check for missing Host header in HTTP/1.1
    if ( version == "1.1" && ! c?$http$host )
        {
        NOTICE([$note=Missing_HTTP_Header,
                $msg=fmt("HTTP/1.1 request missing Host header from %s", c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h)]);
        }
    
    # Detect SQL injection attempts
    if ( /(\bselect\b|\bunion\b|\bor\b.*=|'.*or.*'.*=.*')/i in unescaped_URI )
        {
        NOTICE([$note=SQL_Injection_Attempt,
                $msg=fmt("Potential SQL injection attempt from %s: %s", c$id$orig_h, unescaped_URI),
                $conn=c,
                $identifier=cat(c$id$orig_h, unescaped_URI)]);
        }
    
    # Detect directory traversal attempts
    if ( /\.\.\/|\.\.\\/ in unescaped_URI )
        {
        NOTICE([$note=Directory_Traversal_Attempt,
                $msg=fmt("Directory traversal attempt from %s: %s", c$id$orig_h, unescaped_URI),
                $conn=c,
                $identifier=cat(c$id$orig_h, unescaped_URI)]);
        }
    }

# Detect DNS tunneling through unusually long queries
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( |query| > 50 )
        {
        NOTICE([$note=DNS_Tunneling_Suspected,
                $msg=fmt("Suspiciously long DNS query from %s: %s (%d chars)", c$id$orig_h, query, |query|),
                $conn=c,
                $identifier=cat(c$id$orig_h, query)]);
        }
    }

# Check for missing User-Agent in HTTP requests
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( is_orig && name == "USER-AGENT" )
        {
        # Mark that we've seen a User-Agent
        if ( ! c?$http )
            return;
        # This is handled internally by Zeek
        }
    }

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    if ( is_orig && c?$http )
        {
        local has_ua = F;
        for ( i in hlist )
            {
            if ( hlist[i]$name == "USER-AGENT" )
                has_ua = T;
            }
        
        if ( ! has_ua )
            {
            NOTICE([$note=Missing_HTTP_Header,
                    $msg=fmt("HTTP request missing User-Agent header from %s", c$id$orig_h),
                    $conn=c,
                    $identifier=cat(c$id$orig_h, c$id$resp_h, "no-ua")]);
            }
        }
    }
