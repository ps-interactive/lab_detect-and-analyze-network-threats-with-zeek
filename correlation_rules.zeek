##! Correlation rules for detecting complex attack patterns

module CorrelationRules;

export {
    redef enum Notice::Type += {
        SSH_Brute_Force,
        Multi_Stage_Attack,
        C2_Beacon_Pattern,
        Successful_Brute_Force
    };
    
    # Track SSH attempts
    global ssh_attempts: table[addr] of count &default=0 &create_expire=10min;
    global ssh_failures: table[addr] of count &default=0 &create_expire=10min;
    
    # Track multi-stage attacks
    global attack_stages: table[addr] of set[string] &create_expire=30min;
    
    # Track beacon patterns
    global beacon_times: table[addr, addr, port] of vector of time &create_expire=1hr;
}

# Detect SSH brute force attempts
event ssh_auth_attempted(c: connection, authenticated: bool)
    {
    local src = c$id$orig_h;
    
    ssh_attempts[src] += 1;
    
    if ( ! authenticated )
        ssh_failures[src] += 1;
    
    # Alert on brute force pattern
    if ( ssh_attempts[src] >= 10 && ssh_failures[src] >= 8 )
        {
        NOTICE([$note=SSH_Brute_Force,
                $msg=fmt("SSH brute force attack from %s (%d attempts, %d failures)", 
                         src, ssh_attempts[src], ssh_failures[src]),
                $conn=c,
                $identifier=cat(src, "ssh-brute")]);
        
        # Check if eventually successful
        if ( ssh_attempts[src] > ssh_failures[src] )
            {
            NOTICE([$note=Successful_Brute_Force,
                    $msg=fmt("Successful SSH brute force from %s after %d attempts", 
                             src, ssh_attempts[src]),
                    $conn=c,
                    $identifier=cat(src, "ssh-success")]);
            }
        
        delete ssh_attempts[src];
        delete ssh_failures[src];
        }
    }

# Correlate different attack stages
event PortScan::Vertical_Port_Scan(n: Notice::Info)
    {
    local attacker = n$src;
    
    if ( attacker !in attack_stages )
        attack_stages[attacker] = set();
    
    add attack_stages[attacker]["port_scan"];
    check_multi_stage(attacker);
    }

event ProtocolAnomaly::SQL_Injection_Attempt(n: Notice::Info)
    {
    if ( n?$conn )
        {
        local attacker = n$conn$id$orig_h;
        
        if ( attacker !in attack_stages )
            attack_stages[attacker] = set();
        
        add attack_stages[attacker]["sql_injection"];
        check_multi_stage(attacker);
        }
    }

function check_multi_stage(attacker: addr)
    {
    if ( attacker in attack_stages && |attack_stages[attacker]| >= 2 )
        {
        local stages_str = "";
        for ( stage in attack_stages[attacker] )
            stages_str = fmt("%s %s", stages_str, stage);
        
        NOTICE([$note=Multi_Stage_Attack,
                $msg=fmt("Multi-stage attack detected from %s: %s", attacker, stages_str),
                $src=attacker,
                $identifier=cat(attacker, "multi-stage")]);
        }
    }

# Detect C2 beacon patterns
event connection_established(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dport = c$id$resp_p;
    local key = cat(src, dst, dport);
    
    # Track connections to unusual ports
    if ( dport == 4444/tcp || dport == 4445/tcp || dport == 8443/tcp )
        {
        if ( [src, dst, dport] !in beacon_times )
            beacon_times[src, dst, dport] = vector();
        
        beacon_times[src, dst, dport] += network_time();
        
        # Check for regular beacon pattern
        if ( |beacon_times[src, dst, dport]| >= 5 )
            {
            local intervals: vector of interval = vector();
            local times = beacon_times[src, dst, dport];
            
            for ( i in times )
                {
                if ( i > 0 )
                    intervals += times[i] - times[i-1];
                }
            
            # Check if intervals are regular (within 10% variance)
            if ( |intervals| > 0 )
                {
                local avg_interval = 0.0sec;
                for ( j in intervals )
                    avg_interval = avg_interval + intervals[j];
                avg_interval = avg_interval / |intervals|;
                
                local regular = T;
                for ( j in intervals )
                    {
                    if ( intervals[j] < avg_interval * 0.9 || intervals[j] > avg_interval * 1.1 )
                        regular = F;
                    }
                
                if ( regular )
                    {
                    NOTICE([$note=C2_Beacon_Pattern,
                            $msg=fmt("Regular C2 beacon pattern detected: %s -> %s:%s (interval: %s)", 
                                     src, dst, dport, avg_interval),
                            $src=src,
                            $identifier=key]);
                    
                    delete beacon_times[src, dst, dport];
                    }
                }
            }
        }
    }

# Additional correlation for rapid connections
event connection_state_remove(c: connection)
    {
    # Track rapid SSH connections for brute force
    if ( c$id$resp_p == 22/tcp )
        {
        if ( c$conn$conn_state == "REJ" || c$conn$conn_state == "RSTO" || c$conn$conn_state == "S0" )
            {
            # Simulated SSH auth failure for correlation
            event ssh_auth_attempted(c, F);
            }
        else if ( c$conn$conn_state == "SF" && c$conn$duration < 1sec )
            {
            # Quick connection might be failed auth
            event ssh_auth_attempted(c, F);
            }
        else if ( c$conn$conn_state == "SF" && c$conn$duration > 5sec )
            {
            # Longer connection might be successful
            event ssh_auth_attempted(c, T);
            }
        }
    }
