##! Correlate events to detect multi-stage attacks

module CorrelationRules;

export {
    redef enum Notice::Type += {
        Brute_Force_Attack,
        Multi_Stage_Attack,
        C2_Communication
    };
    
    # Track failed login attempts
    global failed_ssh_attempts: table[addr] of count &default=0 &create_expire=10min;
    
    # Track connection patterns for C2 detection
    global beacon_patterns: table[addr] of vector of time &create_expire=1hr;
}

event ssh_auth_failed(c: connection)
{
    local orig = c$id$orig_h;
    failed_ssh_attempts[orig] += 1;
    
    if ( failed_ssh_attempts[orig] >= 10 )
    {
        NOTICE([$note=Brute_Force_Attack,
                $msg=fmt("SSH brute force attack from %s (%d attempts)", 
                        orig, failed_ssh_attempts[orig]),
                $src=orig,
                $identifier=cat(orig, "ssh_brute")]);
    }
}

event connection_established(c: connection)
{
    local orig = c$id$orig_h;
    
    # Check for successful SSH after multiple failures
    if ( c$id$resp_p == 22/tcp && orig in failed_ssh_attempts &&
         failed_ssh_attempts[orig] > 5 )
    {
        NOTICE([$note=Multi_Stage_Attack,
                $msg=fmt("Successful SSH login after %d failed attempts from %s",
                        failed_ssh_attempts[orig], orig),
                $src=orig,
                $conn=c,
                $identifier=cat(orig, "ssh_success")]);
    }
    
    # Track beacon patterns
    if ( c$id$resp_p == 4444/tcp || c$id$resp_p == 8080/tcp )
    {
        if ( orig !in beacon_patterns )
            beacon_patterns[orig] = vector();
        
        beacon_patterns[orig] += network_time();
        
        # Check for regular beacon intervals
        if ( |beacon_patterns[orig]| >= 5 )
        {
            local intervals: vector of interval = vector();
            for ( i in beacon_patterns[orig] )
            {
                if ( i > 0 )
                {
                    local diff = beacon_patterns[orig][i] - beacon_patterns[orig][i-1];
                    intervals += diff;
                }
            }
            
            # Check if intervals are regular (within 10% variance)
            local regular = T;
            if ( |intervals| > 0 )
            {
                local avg_interval = intervals[0];
                for ( j in intervals )
                {
                    if ( j > 0 )
                    {
                        local variance = (intervals[j] - avg_interval) / avg_interval;
                        if ( variance > 0.1 || variance < -0.1 )
                            regular = F;
                    }
                }
                
                if ( regular )
                {
                    NOTICE([$note=C2_Communication,
                            $msg=fmt("Regular beacon pattern detected from %s to port %s",
                                    orig, c$id$resp_p),
                            $src=orig,
                            $conn=c,
                            $identifier=cat(orig, "c2_beacon")]);
                }
            }
        }
    }
}

# Detect multi-stage attacks by correlating different events
event Scan::port_scan_detected(scanner: addr, victim: addr, scanned_ports: set[port])
{
    # Check if scanner later establishes connections
    when ( local c = lookup_connection(scanner, victim) )
    {
        if ( c$orig$state == "ESTAB" )
        {
            NOTICE([$note=Multi_Stage_Attack,
                    $msg=fmt("Connection established after port scan from %s to %s",
                            scanner, victim),
                    $src=scanner,
                    $identifier=cat(scanner, victim, "scan_then_connect")]);
        }
    }
}
