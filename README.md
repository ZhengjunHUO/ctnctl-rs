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
$ cargo build [--features "libbpf-cargo"]
```

## Run
```
# Usage
$ sudo ./target/debug/ctnctl-rs block -h
Add IP to container's blacklist

Usage: ctnctl-rs block [OPTIONS] <--to <IP>|--from <IP>> [CONTAINER_NAME]

Arguments:
  [CONTAINER_NAME]  

Options:
      --to <IP>         visit an external IP from container
      --from <IP>       be visited from a remote IP
      --tcp <TCP_PORT>  specify a tcp port
      --udp <UDP_PORT>  specify a udp port
  -h, --help            Print help
  -V, --version         Print version

# Block container from visiting some IP
$ sudo ./target/debug/ctnctl-rs block --to 8.8.4.4 ctn1
# Blacklist some remote IP to visit target container on some port
$ sudo ./target/debug/ctnctl-rs block --from 172.17.0.2 --tcp 8000 ctn2

# Show active rules
$ sudo ./target/debug/ctnctl-rs show ctn1
L3 Egress (to) firewall rules: 
  - 8.8.4.4

L3 Ingress (from) firewall rules: 

L4 Egress (to) firewall rules: 

L4 Ingress (from) firewall rules: 

$ sudo ./target/debug/ctnctl-rs show ctn2
L3 Egress (to) firewall rules: 

L3 Ingress (from) firewall rules: 

L4 Egress (to) firewall rules: 

L4 Ingress (from) firewall rules: 
  - 172.17.0.2:8000 (TCP)

# Remove all rules applied to the container
$ sudo ./target/debug/ctnctl-rs clear ctn1

# When container doesn't exist
$ sudo ./target/debug/ctnctl-rs clear rust
Error: Container rust not found !
```
