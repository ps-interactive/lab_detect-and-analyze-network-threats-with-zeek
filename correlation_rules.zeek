##! Correlation rules for detecting multi-stage attacks
##! Correlates multiple events to identify complex attack patterns

module CorrelationRules;

export {
    redef enum Notice::Type += {
        SSH_Brute_Force,
        Multi_Stage_Attack,
        C2_Beacon_Pattern
    };
    
    # Thresholds
    const ssh_attempt_threshold = 5 &redef;
    const beacon_count_threshold = 3 &redef;
}

# Track SSH attempts
global ssh_attempts: table[addr, addr] of count &create_expire=10min &default=0;

# Track connection patterns for beacon detection  
global beacon_connections: table[addr, addr, port] of count &create_expire=30min &default=0;

event connection_state_remove(c: connection) {
    # Detect SSH brute force (multiple connections to port 22)
    if (c$id$resp_p == 22/tcp) {
        local ssh_key = [c$id$orig_h, c$id$resp_h];
        ++ssh_attempts[ssh_key];
        
        if (ssh_attempts[ssh_key] >= ssh_attempt_threshold) {
            NOTICE([$note=SSH_Brute_Force,
                    $msg=fmt("SSH brute force detected: %s -> %s (%d attempts)", 
                            c$id$orig_h, c$id$resp_h, ssh_attempts[ssh_key]),
                    $conn=c,
                    $identifier=cat(c$id$orig_h, c$id$resp_h, "ssh_brute")]);
            delete ssh_attempts[ssh_key];
        }
    }
    
    # Track potential C2 beacons (repeated connections to same port)
    local beacon_key = [c$id$orig_h, c$id$resp_h, c$id$resp_p];
    ++beacon_connections[beacon_key];
    
    if (beacon_connections[beacon_key] >= beacon_count_threshold) {
        # Check if it's on a suspicious port
        if (c$id$resp_p == 4444/tcp || c$id$resp_p == 8443/tcp || 
            c$id$resp_p == 1337/tcp || c$id$resp_p == 31337/tcp) {
            NOTICE([$note=C2_Beacon_Pattern,
                    $msg=fmt("Potential C2 beacon: %s -> %s:%s (%d connections)",
                            c$id$orig_h, c$id$resp_h, c$id$resp_p, 
                            beacon_connections[beacon_key]),
                    $conn=c,
                    $identifier=cat(c$id$orig_h, c$id$resp_h, c$id$resp_p, "beacon")]);
            beacon_connections[beacon_key] = 0;
        }
    }
}
