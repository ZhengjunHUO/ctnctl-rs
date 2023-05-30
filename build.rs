fn main() {
    build_and_generate();
}

#[cfg(feature = "libbpf-cargo")]
fn build_and_generate() {
    use libbpf_cargo::SkeletonBuilder;
    use std::env;
    use std::path::PathBuf;

    let c_prog = "src/bpf/cgroup_fw.bpf.c";
    let src_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out = src_dir.join("src/cgroup_fw.skel.rs");

    SkeletonBuilder::new()
        .source(c_prog)
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={c_prog}");
}

#[cfg(not(feature = "libbpf-cargo"))]
fn build_and_generate() {}
