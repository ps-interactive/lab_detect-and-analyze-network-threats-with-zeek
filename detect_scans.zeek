##! Detect port scanning activities in network traffic

module PortScan;

export {
    redef enum Notice::Type += {
        Vertical_Port_Scan,
        Horizontal_Port_Scan
    };
    
    # Thresholds for detection
    const vertical_scan_threshold = 10 &redef;
    const horizontal_scan_threshold = 5 &redef;
    const scan_interval = 5min &redef;
    
    # Track scanning activity
    global scan_attempts: table[addr] of set[port] &create_expire=scan_interval;
    global host_attempts: table[addr] of set[addr] &create_expire=scan_interval;
}

event connection_attempt(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dport = c$id$resp_p;
    
    # Track vertical scanning (many ports on one host)
    if ( src !in scan_attempts )
        scan_attempts[src] = set();
    
    add scan_attempts[src][dport];
    
    if ( |scan_attempts[src]| >= vertical_scan_threshold )
        {
        NOTICE([$note=Vertical_Port_Scan,
                $msg=fmt("Vertical port scan detected from %s (scanned %d ports)", src, |scan_attempts[src]|),
                $src=src,
                $identifier=cat(src)]);
        delete scan_attempts[src];
        }
    
    # Track horizontal scanning (many hosts on same port)
    if ( src !in host_attempts )
        host_attempts[src] = set();
    
    add host_attempts[src][dst];
    
    if ( |host_attempts[src]| >= horizontal_scan_threshold )
        {
        NOTICE([$note=Horizontal_Port_Scan,
                $msg=fmt("Horizontal port scan detected from %s (scanned %d hosts)", src, |host_attempts[src]|),
                $src=src,
                $identifier=cat(src)]);
        delete host_attempts[src];
        }
    }

event connection_state_remove(c: connection)
    {
    # Detect failed connections that might indicate scanning
    if ( c$conn$conn_state == "S0" || c$conn$conn_state == "REJ" || c$conn$conn_state == "RSTO" )
        {
        event connection_attempt(c);
        }
    }
