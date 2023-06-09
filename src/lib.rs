pub mod actions;
mod rule;
mod sys;
mod utils;

const BPF_PATH: &str = "/sys/fs/bpf";
const EGRESS_MAP_NAME: &str = "cgroup_egs_map";
const INGRESS_MAP_NAME: &str = "cgroup_igs_map";
const EGRESS_L4_MAP_NAME: &str = "cgroup_egs_l4_map";
const INGRESS_L4_MAP_NAME: &str = "cgroup_igs_l4_map";
const EGRESS_LINK_NAME: &str = "cgroup_egs_link";
const INGRESS_LINK_NAME: &str = "cgroup_igs_link";
const DATAFLOW_MAP_NAME: &str = "data_flow_map";
const ICMP_PROTO: u8 = 1;
const TCP_PROTO: u8 = 6;
const UDP_PROTO: u8 = 17;
