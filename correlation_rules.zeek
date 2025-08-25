##! Correlation rules for detecting multi-stage attacks
##! Correlates multiple events to identify complex attack patterns

module CorrelationRules;

export {
    redef enum Notice::Type += {
        SSH_Brute_Force,
        Multi_Stage_Attack,
        C2_Beacon_Pattern,
        Data_Exfiltration
    };
    
    # Thresholds
    const ssh_attempt_threshold = 5 &redef;
    const beacon_interval_variance = 10.0 &redef;  # seconds
    const exfil_size_threshold = 1000000 &redef;   # 1MB
}

# Track SSH attempts
global ssh_attempts: table[addr, addr] of count &create_expire=10min &default=0;

# Track connection patterns for beacon detection
global connection_times: table[addr, addr, port] of vector of time &create_expire=30min;

# Track multi-stage attack indicators
type AttackStage: record {
    scan_detected: bool &default=F;
    exploit_attempt: bool &default=F;
    backdoor_installed: bool &default=F;
    data_exfil: bool &default=F;
};

global attack_stages: table[addr] of AttackStage &create_expire=1hr;

# Detect SSH brute force
event ssh_auth_failed(c: connection) {
    local key = [c$id$orig_h, c$id$resp_h];
    ++ssh_attempts[key];
    
    if (ssh_attempts[key] >= ssh_attempt_threshold) {
        NOTICE([$note=SSH_Brute_Force,
                $msg=fmt("SSH brute force detected: %s -> %s (%d attempts)", 
                        c$id$orig_h, c$id$resp_h, ssh_attempts[key]),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h, "ssh_brute")]);
        
        # Mark as potential multi-stage attack
        if (c$id$orig_h !in attack_stages) {
            attack_stages[c$id$orig_h] = AttackStage();
        }
        attack_stages[c$id$orig_h]$exploit_attempt = T;
    }
}

# Detect C2 beacon patterns
event connection_state_remove(c: connection) {
    local key = [c$id$orig_h, c$id$resp_h, c$id$resp_p];
    
    # Track connection times for beacon detection
    if (key !in connection_times) {
        connection_times[key] = vector();
    }
    connection_times[key] += network_time();
    
    # Check for regular beacon intervals
    if (|connection_times[key]| >= 5) {
        local intervals: vector of interval = vector();
        for (i in [1..|connection_times[key]|-1]) {
            intervals += connection_times[key][i] - connection_times[key][i-1];
        }
        
        # Calculate average interval
        local sum_interval = 0.0;
        for (i in intervals) {
            sum_interval += interval_to_double(intervals[i]);
        }
        local avg_interval = sum_interval / |intervals|;
        
        # Check variance
        local variance = 0.0;
        for (i in intervals) {
            local diff = interval_to_double(intervals[i]) - avg_interval;
            variance += diff * diff;
        }
        variance = variance / |intervals|;
        
        # Low variance indicates regular beaconing
        if (variance < beacon_interval_variance) {
            NOTICE([$note=C2_Beacon_Pattern,
                    $msg=fmt("Regular beacon pattern detected: %s -> %s:%s (avg interval: %.1f sec)",
                            c$id$orig_h, c$id$resp_h, c$id$resp_p, avg_interval),
                    $conn=c,
                    $identifier=cat(c$id$orig_h, c$id$resp_h, c$id$resp_p, "beacon")]);
            
            # Mark as backdoor installed
            if (c$id$orig_h !in attack_stages) {
                attack_stages[c$id$orig_h] = AttackStage();
            }
            attack_stages[c$id$orig_h]$backdoor_installed = T;
        }
    }
    
    # Check for data exfiltration
    if (c$conn?$orig_bytes && c$conn$orig_bytes > exfil_size_threshold) {
        NOTICE([$note=Data_Exfiltration,
                $msg=fmt("Large data transfer detected: %s -> %s (%d bytes)",
                        c$id$orig_h, c$id$resp_h, c$conn$orig_bytes),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h, "exfil")]);
        
        if (c$id$orig_h !in attack_stages) {
            attack_stages[c$id$orig_h] = AttackStage();
        }
        attack_stages[c$id$orig_h]$data_exfil = T;
    }
}

# Correlate events for multi-stage attack detection
event Scan_Detection::Vertical_Port_Scan(n: Notice::Info) {
    if (n$src !in attack_stages) {
        attack_stages[n$src] = AttackStage();
    }
    attack_stages[n$src]$scan_detected = T;
    check_multi_stage(n$src);
}

function check_multi_stage(attacker: addr) {
    if (attacker !in attack_stages) {
        return;
    }
    
    local stages = attack_stages[attacker];
    local stage_count = 0;
    
    if (stages$scan_detected) ++stage_count;
    if (stages$exploit_attempt) ++stage_count;
    if (stages$backdoor_installed) ++stage_count;
    if (stages$data_exfil) ++stage_count;
    
    if (stage_count >= 2) {
        NOTICE([$note=Multi_Stage_Attack,
                $msg=fmt("Multi-stage attack detected from %s (%d stages identified)", 
                        attacker, stage_count),
                $src=attacker,
                $identifier=cat(attacker, "multi_stage")]);
    }
}

# Periodic check for multi-stage attacks
event zeek_done() {
    for (attacker in attack_stages) {
        check_multi_stage(attacker);
    }
}
