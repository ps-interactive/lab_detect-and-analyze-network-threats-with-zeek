##! Correlation rules for detecting complex multi-stage attacks
##! This script correlates various events to identify attack patterns

@load base/frameworks/notice
@load base/frameworks/intel

module AttackCorrelation;

export {
    redef enum Notice::Type += {
        ## Brute force attack detected
        Brute_Force_Attack,
        ## Potential C2 communication detected
        C2_Communication,
        ## Multi-stage attack detected
        Multi_Stage_Attack,
        ## Data exfiltration suspected
        Data_Exfiltration
    };
    
    ## Track failed authentication attempts
    global failed_auth_attempts: table[addr] of count &create_expire=300.0 &default=0;
    
    ## Track successful connections after failures
    global post_fail_success: set[addr] &create_expire=600.0;
    
    ## Track potential C2 beacons
    global beacon_tracking: table[addr] of vector of time &create_expire=3600.0;
    
    ## Threshold for brute force detection
    const brute_force_threshold = 10 &redef;
    
    ## Threshold for beacon regularity (in seconds)
    const beacon_interval_threshold = 5.0 &redef;
}

# Track SSH brute force attempts
event connection_state_remove(c: connection)
{
    if ( c$id$resp_p == 22/tcp )
    {
        local src = c$id$orig_h;
        
        # Connection was rejected or reset quickly
        if ( c$conn$history == "Sr" || c$conn$history == "ShR" )
        {
            failed_auth_attempts[src] += 1;
            
            if ( failed_auth_attempts[src] >= brute_force_threshold )
            {
                NOTICE([$note=Brute_Force_Attack,
                        $msg=fmt("SSH brute force attack from %s (%d attempts)", 
                                src, failed_auth_attempts[src]),
                        $src=src,
                        $conn=c,
                        $identifier=cat(src)]);
            }
        }
        # Successful connection after multiple failures
        else if ( c$conn$history == "ShAdFr" && src in failed_auth_attempts &&
                  failed_auth_attempts[src] > 5 )
        {
            add post_fail_success[src];
            
            NOTICE([$note=Multi_Stage_Attack,
                    $msg=fmt("Successful SSH after %d failed attempts from %s", 
                            failed_auth_attempts[src], src),
                    $src=src,
                    $conn=c,
                    $identifier=cat(src)]);
        }
    }
}

# Detect potential C2 beacons based on regular intervals
event connection_established(c: connection)
{
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    
    # Track connections to external IPs on unusual ports
    if ( ! Site::is_local_addr(dst) && 
         c$id$resp_p != 80/tcp && c$id$resp_p != 443/tcp )
    {
        if ( src !in beacon_tracking )
            beacon_tracking[src] = vector();
        
        beacon_tracking[src] += network_time();
        
        # Check for regular intervals
        if ( |beacon_tracking[src]| >= 3 )
        {
            local intervals: vector of interval = vector();
            
            for ( i in beacon_tracking[src] )
            {
                if ( i > 0 )
                {
                    local diff = beacon_tracking[src][i] - beacon_tracking[src][i-1];
                    intervals += diff;
                }
            }
            
            # Check if intervals are regular (within threshold)
            local regular = T;
            if ( |intervals| >= 2 )
            {
                local first_interval = intervals[0];
                for ( j in intervals )
                {
                    if ( j > 0 )
                    {
                        local interval_diff = intervals[j] > first_interval ? 
                                             intervals[j] - first_interval : 
                                             first_interval - intervals[j];
                        
                        if ( interval_diff > beacon_interval_threshold )
                            regular = F;
                    }
                }
                
                if ( regular )
                {
                    NOTICE([$note=C2_Communication,
                            $msg=fmt("Regular beacon pattern detected from %s to %s:%s", 
                                    src, dst, c$id$resp_p),
                            $src=src,
                            $conn=c,
                            $identifier=cat(src, dst)]);
                }
            }
        }
    }
}

# Detect potential data exfiltration
event connection_state_remove(c: connection)
{
    # Large outbound data transfer to external host
    if ( c$conn?$orig_bytes && c$conn?$resp_bytes )
    {
        local src = c$id$orig_h;
        local dst = c$id$resp_h;
        
        if ( Site::is_local_addr(src) && ! Site::is_local_addr(dst) )
        {
            # Suspicious if large upload (> 10MB) with small download
            if ( c$conn$orig_bytes > 10485760 && 
                 c$conn$resp_bytes < c$conn$orig_bytes / 10 )
            {
                NOTICE([$note=Data_Exfiltration,
                        $msg=fmt("Large data upload from %s to %s (%d bytes)", 
                                src, dst, c$conn$orig_bytes),
                        $src=src,
                        $conn=c,
                        $identifier=cat(c$uid)]);
            }
        }
    }
}

# Correlate scan + exploit + C2
event Notice::notice(n: Notice::Info)
{
    # If we see a scan, then successful connection, then C2 behavior
    # from the same source, it's likely a multi-stage attack
    
    if ( n$note == PortScan::Port_Scan && n?$src )
    {
        # Mark this host as a scanner for correlation
        # In production, you'd track this more sophisticatedly
        
        when ( local result = lookup_addr(n$src) )
        {
            # Additional correlation logic would go here
        }
    }
    
    # Check if a scanner later establishes C2
    if ( n$note == C2_Communication && n?$src )
    {
        # If this host was previously seen scanning
        # This would require more sophisticated state tracking
        # For the lab, we'll demonstrate the concept
    }
}
