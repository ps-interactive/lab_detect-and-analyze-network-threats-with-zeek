##! Detect port scanning activity
##! This script identifies potential port scans based on connection patterns

@load base/frameworks/notice

module PortScan;

export {
    redef enum Notice::Type += {
        ## Port scan detected
        Port_Scan,
        ## Vertical scan detected (multiple ports, single host)
        Vertical_Scan,
        ## Horizontal scan detected (single port, multiple hosts)  
        Horizontal_Scan
    };
    
    ## Threshold for number of ports before alerting
    const scan_threshold = 5 &redef;
    
    ## Time window for scan detection (in seconds)
    const scan_window = 60.0 &redef;
    
    ## Track scanning activity
    global scanner_activity: table[addr] of set[port] &create_expire=scan_window;
    global horizontal_scanners: table[addr] of set[addr] &create_expire=scan_window;
}

event connection_attempt(c: connection)
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dport = c$id$resp_p;
    
    # Track vertical scanning (many ports on same host)
    if ( src !in scanner_activity )
        scanner_activity[src] = set();
    
    add scanner_activity[src][dport];
    
    if ( |scanner_activity[src]| >= scan_threshold )
    {
        NOTICE([$note=Vertical_Scan,
                $msg=fmt("%s is scanning multiple ports on %s", src, dst),
                $src=src,
                $identifier=cat(src)]);
    }
}

event connection_rejected(c: connection)
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    
    # Track horizontal scanning (same port on many hosts)
    if ( src !in horizontal_scanners )
        horizontal_scanners[src] = set();
    
    add horizontal_scanners[src][dst];
    
    if ( |horizontal_scanners[src]| >= scan_threshold )
    {
        NOTICE([$note=Horizontal_Scan,
                $msg=fmt("%s is scanning multiple hosts", src),
                $src=src,
                $identifier=cat(src)]);
    }
}

event connection_state_remove(c: connection)
{
    # Detect SYN scans (connections that never complete)
    if ( c$conn$history == "S" || c$conn$history == "Sr" )
    {
        local src = c$id$orig_h;
        
        if ( src in scanner_activity && |scanner_activity[src]| >= 3 )
        {
            NOTICE([$note=Port_Scan,
                    $msg=fmt("Potential SYN scan from %s", src),
                    $src=src,
                    $conn=c,
                    $identifier=cat(src)]);
        }
    }
}
