module ProtocolAnomaly;
export {
    redef enum Notice::Type += { Protocol_Mismatch, Missing_Protocol_Field };
}
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if (version == "1.1" && !c$http?$host) {
        NOTICE([$note=Missing_Protocol_Field, $msg="Missing Host header", $conn=c]);
    }
}
