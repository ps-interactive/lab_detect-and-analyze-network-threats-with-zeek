module CorrelationRules;
export {
    redef enum Notice::Type += { Brute_Force_Attack, Multi_Stage_Attack, C2_Communication };
}
event connection_established(c: connection) {
    if (c$id$resp_p == 22/tcp) {
        NOTICE([$note=Brute_Force_Attack, $msg=fmt("SSH activity from %s", c$id$orig_h), $src=c$id$orig_h]);
    }
}
