##! Simple port scan detection script for Zeek

@load base/frameworks/notice

module ScanDetection;

export {
    redef enum Notice::Type += {
        Port_Scan
    };
    
    # Threshold for detection
    const scan_threshold = 10 &redef;
}

# Track scanning activity
global scan_count: table[addr] of count &default=0;

event connection_state_remove(c: connection) {
    local orig = c$id$orig_h;
    local resp_port = c$id$resp_p;
    
    # Count connection attempts from each source
    scan_count[orig] += 1;
    
    # Alert if threshold exceeded
    if (scan_count[orig] == scan_threshold) {
        NOTICE([$note=Port_Scan,
                $msg=fmt("Port scan detected from %s (%d connections)", orig, scan_count[orig]),
                $src=orig,
                $identifier=cat(orig)]);
    }
}
