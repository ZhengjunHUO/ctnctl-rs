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
  block  Add IP to container's blacklist
  clear  Remove container's all firewall rules
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

# Block container from visiting some IP
$ sudo ./target/debug/ctnctl-rs block --to 8.8.4.4 ctn1
# Blacklist some remote IP to visit target container
$ sudo ./target/debug/ctnctl-rs block --from 172.17.0.2 ctn2

# Remove all rules applied to the container
$ sudo ./target/debug/ctnctl-rs clear ctn1

# When container doesn't exist
$ sudo ./target/debug/ctnctl-rs clear rust
Error: Container rust not found !
```
