use super::*;
use anyhow::{bail, Result};
use std::net::Ipv4Addr;

/// Convert ipv4 address to a four element byte array
pub fn ipv4_to_u32(ip: &str) -> Result<[u8; 4]> {
    use std::str::FromStr;

    let ip_parsed = Ipv4Addr::from_str(ip)?;
    Ok(u32::from(ip_parsed).to_be_bytes())
}

/// Build a key for the bpf hashmap from ip, port and protocol
///
/// The related struct in bpf program:
/// ```text
/// typedef struct {
///     __u32 addr;
///     __u16 port;
///     __u8 proto;
///     __u8 reserved;
/// } skt;
/// ```
pub fn skt_to_u64(ip: &str, port: u16, is_udp: bool) -> Result<[u8; 8]> {
    let ip_parsed = ipv4_to_u32(ip)?;
    let port_parsed: [u8; 2] = port.to_be_bytes();
    let proto: u8 = if is_udp { UDP_PROTO } else { TCP_PROTO };

    let mut rslt: [u8; 8] = [0; 8];
    rslt[..4].copy_from_slice(&ip_parsed);
    rslt[4..6].copy_from_slice(&port_parsed);
    rslt[6] = proto;
    Ok(rslt)
}

/// Convert a four element byte array to ipv4 address
pub fn u32_to_ipv4(v: &[u8]) -> Result<String> {
    if v.len() != 4 {
        bail!("Unexpected key stored in the map: {:?}", v)
    }

    let ip = Ipv4Addr::from([v[0], v[1], v[2], v[3]]);
    Ok(ip.to_string())
}

/// Parse a byte array to a `<IP>:<PORT> (<TCP>|<UDP>)` String
pub fn u64_to_skt(v: &[u8]) -> Result<String> {
    if v.len() != 8 {
        bail!("Unexpected key stored in the map: {:?}", v)
    }

    let ip = Ipv4Addr::from([v[0], v[1], v[2], v[3]]).to_string();
    let proto = match v[6] {
        TCP_PROTO => "TCP",
        UDP_PROTO => "UDP",
        _ => "UNKNOWN",
    };
    let skt = format!("{}:{} ({})", ip, u16::from_be_bytes([v[4], v[5]]), proto);
    Ok(skt)
}

/// Parse a byte array to an log entry showing the network packet flow
///
/// The related struct in bpf program:
/// ```text
/// typedef struct {
///     __u32 saddr;
///     __u32 daddr;
///     __u16 sport;
///     __u16 dport;
///     __u8 proto;
///     __u8 bitmap;
/// } pkt;
///
/// bitmap:
///  00000000
///       |||- isIngress
///       ||-- isBannedL3
///       |--- isBannedL4
/// ```
pub fn parse_pkt(pkt: &[u8]) -> Result<String> {
    if pkt.len() != 16 {
        bail!("Unexpected pkt stored in the map: {:?}", pkt)
    }

    let src_ip = Ipv4Addr::from([pkt[0], pkt[1], pkt[2], pkt[3]]).to_string();
    let dst_ip = Ipv4Addr::from([pkt[4], pkt[5], pkt[6], pkt[7]]).to_string();
    let src_port = u16::from_be_bytes([pkt[8], pkt[9]]);
    let dst_port = u16::from_be_bytes([pkt[10], pkt[11]]);
    let proto = match pkt[12] {
        TCP_PROTO => "TCP",
        UDP_PROTO => "UDP",
        ICMP_PROTO => "ICMP",
        _ => "UNKNOWN",
    };
    let is_ingress = { (pkt[13] & 1) == 1 };
    let is_banned_l3 = { ((pkt[13] & 2) >> 1) == 1 };
    let is_banned_l4 = { ((pkt[13] & 4) >> 2) == 1 };

    let mut result;
    match (is_ingress, proto) {
        (true, "ICMP") => result = format!("{} IN {} < {}", proto, dst_ip, src_ip),
        (true, _) => {
            result = format!(
                "{} IN {}:{} < {}:{}",
                proto, dst_ip, dst_port, src_ip, src_port
            )
        }
        (false, "ICMP") => result = format!("{} OUT {} > {}", proto, src_ip, dst_ip),
        (false, _) => {
            result = format!(
                "{} OUT {}:{} > {}:{}",
                proto, src_ip, src_port, dst_ip, dst_port
            )
        }
    }

    if is_banned_l3 {
        result.push_str(" (BANNED L3)");
    }

    if is_banned_l4 {
        result.push_str(" (BANNED L4)");
    }

    Ok(result)
}

/// Return a list of all pinned map
pub fn get_all_maps() -> Vec<&'static str> {
    let mut v = get_rule_maps();
    v.push(DATAFLOW_MAP_NAME);
    v
}

/// Return a list of pinned map containing the firewall rules
pub fn get_rule_maps() -> Vec<&'static str> {
    vec![
        EGRESS_MAP_NAME,
        INGRESS_MAP_NAME,
        EGRESS_L4_MAP_NAME,
        INGRESS_L4_MAP_NAME,
    ]
}

/// Return a path containing all pinned resource related to container
pub fn get_ctn_bpf_path(ctn_id: &str) -> String {
    format!("{}/{}", BPF_PATH, ctn_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_ipv4_u32() {
        let ip = "172.16.0.10";
        let expect: [u8; 4] = [172, 16, 0, 10];
        let rslt = ipv4_to_u32(&ip).expect("Failed to parse ip");
        assert_eq!(rslt.len(), 4);
        assert_eq!(rslt, expect);

        let restored = u32_to_ipv4(&rslt).expect("Failed to restore back to ip");
        assert_eq!(ip, restored);
    }

    #[test]
    fn test_convert_skt_u64() {
        let ip = "172.17.0.3";
        // 8088 => 00011111 10011000
        let expect: [u8; 8] = [172, 17, 0, 3, 31, 152, 17, 0];
        let rslt = skt_to_u64(&ip, 8088, true).expect("Failed to parse ip");
        assert_eq!(rslt.len(), 8);
        assert_eq!(rslt, expect);

        let restored = u64_to_skt(&rslt).expect("Failed to restore back to ip:port");
        let expect_output = "172.17.0.3:8088 (UDP)";
        assert_eq!(restored, expect_output);
    }

    #[test]
    fn test_parse_pkt() {
        let pkt: [u8; 16] = [10, 20, 0, 1, 10, 20, 0, 8, 121, 24, 31, 152, 6, 5, 0, 0];
        let expect = "TCP IN 10.20.0.8:8088 < 10.20.0.1:31000 (BANNED L4)";
        let rslt = parse_pkt(&pkt).expect("Failed to parse the packet");
        assert_eq!(rslt, expect);
    }
}
