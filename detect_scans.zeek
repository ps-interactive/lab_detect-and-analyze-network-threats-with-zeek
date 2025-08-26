##! Port scan detection script for Zeek
##! Detects both vertical (many ports on one host) and horizontal (one port on many hosts) scans

module ScanDetection;

export {
    redef enum Notice::Type += {
        Vertical_Port_Scan,
        Horizontal_Port_Scan
    };
    
    # Thresholds for detection
    const vertical_scan_threshold = 10 &redef;
    const horizontal_scan_threshold = 5 &redef;
    const scan_interval = 5min &redef;
}

# Track connection attempts
global port_scanners: table[addr] of set[port] &create_expire=scan_interval;
global horizontal_scanners: table[addr, port] of set[addr] &create_expire=scan_interval;

event connection_state_remove(c: connection) {
    # Only track failed or unusual connections
    if (c$conn$conn_state != "SF" && c$conn$conn_state != "S1" && 
        c$conn$conn_state != "S2" && c$conn$conn_state != "S3") {
        return;
    }
    
    local orig = c$id$orig_h;
    local resp = c$id$resp_h;
    local resp_port = c$id$resp_p;
    
    # Track vertical scanning (many ports on single host)
    if (orig !in port_scanners) {
        port_scanners[orig] = set();
    }
    add port_scanners[orig][resp_port];
    
    if (|port_scanners[orig]| >= vertical_scan_threshold) {
        NOTICE([$note=Vertical_Port_Scan,
                $msg=fmt("Vertical port scan detected from %s (scanned %d ports)", orig, |port_scanners[orig]|),
                $src=orig,
                $identifier=cat(orig)]);
        delete port_scanners[orig];
    }
    
    # Track horizontal scanning (same port on many hosts)
    local key = [orig, resp_port];
    if (key !in horizontal_scanners) {
        horizontal_scanners[key] = set();
    }
    add horizontal_scanners[key][resp];
    
    if (|horizontal_scanners[key]| >= horizontal_scan_threshold) {
        NOTICE([$note=Horizontal_Port_Scan,
                $msg=fmt("Horizontal port scan detected from %s on port %s (scanned %d hosts)", 
                        orig, resp_port, |horizontal_scanners[key]|),
                $src=orig,
                $identifier=cat(orig, resp_port)]);
        delete horizontal_scanners[key];
    }
}
