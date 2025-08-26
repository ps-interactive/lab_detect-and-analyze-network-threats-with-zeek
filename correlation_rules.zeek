##! Correlation rules for detecting attacks

@load base/frameworks/notice

module CorrelationRules;

export {
    redef enum Notice::Type += {
        SSH_Brute_Force,
        C2_Beacon
    };
    
    const ssh_threshold = 10 &redef;
}

# Track SSH attempts
global ssh_attempts: table[addr] of count &default=0;

event connection_state_remove(c: connection) {
    local orig = c$id$orig_h;
    local resp_port = c$id$resp_p;
    
    # Track SSH connections
    if (resp_port == 22/tcp) {
        ssh_attempts[orig] += 1;
        
        if (ssh_attempts[orig] == ssh_threshold) {
            NOTICE([$note=SSH_Brute_Force,
                    $msg=fmt("SSH brute force detected from %s (%d attempts)", orig, ssh_attempts[orig]),
                    $src=orig,
                    $identifier=cat(orig, "ssh")]);
        }
    }
    
    # Simple C2 beacon detection (port 4444)
    if (resp_port == 4444/tcp) {
        NOTICE([$note=C2_Beacon,
                $msg=fmt("Potential C2 communication from %s to port 4444", orig),
                $src=orig,
                $identifier=cat(orig, "c2")]);
    }
}
