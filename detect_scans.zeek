##! Detect port and host scanning activities

module DetectScans;

export {
    redef enum Notice::Type += {
        Port_Scan,
        Host_Scan
    };
    
    # Thresholds for detection
    const port_scan_threshold = 10 &redef;
    const host_scan_threshold = 5 &redef;
    const scan_interval = 5min &redef;
    
    # Track scanning attempts
    global scan_attempts: table[addr] of set[port] &create_expire = scan_interval;
    global host_attempts: table[addr] of set[addr] &create_expire = scan_interval;
}

event connection_attempt(c: connection)
{
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    local resp_p = c$id$resp_p;
    
    # Track port scanning
    if ( orig !in scan_attempts )
        scan_attempts[orig] = set();
    
    add scan_attempts[orig][resp_p];
    
    if ( |scan_attempts[orig]| >= port_scan_threshold )
    {
        NOTICE([$note=Port_Scan,
                $msg=fmt("Vertical port scan detected from %s", orig),
                $src=orig,
                $identifier=cat(orig)]);
    }
    
    # Track host scanning
    if ( orig !in host_attempts )
        host_attempts[orig] = set();
    
    add host_attempts[orig][resp];
    
    if ( |host_attempts[orig]| >= host_scan_threshold )
    {
        NOTICE([$note=Host_Scan,
                $msg=fmt("Horizontal host scan detected from %s", orig),
                $src=orig,
                $identifier=cat(orig)]);
    }
}

event connection_established(c: connection)
{
    event connection_attempt(c);
}

event connection_rejected(c: connection)
{
    event connection_attempt(c);
}
