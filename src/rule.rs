use super::*;
use crate::utils::*;
use anyhow::Result;
use libbpf_rs::Map;

pub struct Rule {
    ip: String,
    ctn_dir: String,
    port: u16,
    is_l4: bool,
    is_udp: bool,
    is_ingress: bool,
}

impl Rule {
    pub fn map(&self) -> Result<Map> {
        match (self.is_l4, self.is_ingress) {
            (true, true) => {
                return Ok(Map::from_pinned_path(format!(
                    "{}/{}",
                    self.ctn_dir, INGRESS_L4_MAP_NAME
                ))?)
            }
            (true, false) => {
                return Ok(Map::from_pinned_path(format!(
                    "{}/{}",
                    self.ctn_dir, EGRESS_L4_MAP_NAME
                ))?)
            }
            // Open the pinned map for ingress rules inside the container's folder
            (false, true) => {
                return Ok(Map::from_pinned_path(format!(
                    "{}/{}",
                    self.ctn_dir, INGRESS_MAP_NAME
                ))?)
            }
            // Open the pinned map for egress rules inside the container's folder
            (false, false) => {
                return Ok(Map::from_pinned_path(format!(
                    "{}/{}",
                    self.ctn_dir, EGRESS_MAP_NAME
                ))?)
            }
        }
    }

    pub fn key(&self) -> Result<Vec<u8>> {
        match self.is_l4 {
            true => {
                let k = skt_to_u64(&self.ip, self.port, self.is_udp)?;
                return Ok(Vec::from(k));
            }
            false => {
                let k = ipv4_to_u32(&self.ip)?;
                return Ok(Vec::from(k));
            }
        }
    }
}

#[derive(Default)]
pub struct RuleBuilder {
    ip: Option<String>,
    ctn_dir: Option<String>,
    port: Option<u16>,
    pub is_l4: bool,
    pub is_udp: bool,
    pub is_ingress: bool,
}

impl RuleBuilder {
    pub fn new() -> RuleBuilder {
        Default::default()
    }

    pub fn port(mut self, p: u16) -> RuleBuilder {
        self.port = Some(p);
        self
    }

    pub fn ip(mut self, addr: &str) -> RuleBuilder {
        self.ip = Some(addr.to_string());
        self
    }

    pub fn ctn_dir(mut self, dir: &str) -> RuleBuilder {
        self.ctn_dir = Some(dir.to_string());
        self
    }

    pub fn build(self) -> Rule {
        Rule {
            ip: self.ip.unwrap(),
            ctn_dir: self.ctn_dir.unwrap(),
            port: self.port.unwrap_or(0),
            is_l4: self.is_l4,
            is_udp: self.is_udp,
            is_ingress: self.is_ingress,
        }
    }
}
