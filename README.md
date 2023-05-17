# ctnctl-rs
A CLI to apply firewall rules to docker container based on eBPF cgroups in Rust. 
- See the Go version [here](https://github.com/ZhengjunHUO/ctnctl)

## Prerequis
```sh
# On Ubuntu 22.04.2
$ sudo apt install build-essential clang pkgconf zlib1g-dev libelf-dev libbpfcc libbpfcc-dev llvm-dev systemtap-sdt-dev gcc-multilib
```
