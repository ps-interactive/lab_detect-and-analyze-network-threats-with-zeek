module DetectScans;
export {
    redef enum Notice::Type += { Port_Scan, Host_Scan };
    const port_scan_threshold = 10 &redef;
    const host_scan_threshold = 5 &redef;
}
event connection_attempt(c: connection) {
    NOTICE([$note=Port_Scan, $msg=fmt("Port scan from %s", c$id$orig_h), $src=c$id$orig_h]);
}
