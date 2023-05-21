pub mod utils;

pub const BPF_PATH: &str = "/sys/fs/bpf";
pub const EGRESS_MAP_NAME: &str = "cgroup_egs_map";
pub const INGRESS_MAP_NAME: &str = "cgroup_igs_map";
const EGRESS_LINK_NAME: &str = "cgroup_egs_link";
const INGRESS_LINK_NAME: &str = "cgroup_igs_link";
