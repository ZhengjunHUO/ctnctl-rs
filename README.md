# ctnctl-rs
A CLI to apply firewall rules to docker container based on eBPF cgroups in Rust. 
- See the Go version [here](https://github.com/ZhengjunHUO/ctnctl)

## Prerequis
```sh
# On Ubuntu 22.04.2
$ sudo apt install build-essential clang pkgconf zlib1g-dev libelf-dev libbpfcc libbpfcc-dev llvm-dev systemtap-sdt-dev gcc-multilib
```
## Build
```
$ cargo build
```

## Run
```
# Show help info
$ ./target/debug/ctnctl-rs -h
Usage: ctnctl-rs <COMMAND>

Commands:
  block  
  clear  
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

# Block container's egress ip
$ sudo ./target/debug/ctnctl-rs block -e 8.8.4.4 252491db736e3ece6bccbb019c2953d4fa4907f3ba3e3742b00913674fc3e45a

# Remove all rules applied to the container
$ sudo ./target/debug/ctnctl-rs clear 252491db736e3ece6bccbb019c2953d4fa4907f3ba3e3742b00913674fc3e45a
```
