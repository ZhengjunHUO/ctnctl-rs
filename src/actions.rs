use super::*;
use crate::sys::*;
use crate::utils::*;
use anyhow::Result;
use clap::Args;
use crossbeam_channel::{select, tick};
use libbpf_rs::{Link, Map, MapFlags};
use std::path::Path;
use std::time::Duration;

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
pub struct Direction {
    /// visit an external IP from container
    #[clap(long, value_name = "IP")]
    to: Option<String>,

    /// be visited from a remote IP
    #[clap(long, value_name = "IP")]
    from: Option<String>,
}

#[derive(Args, Debug)]
#[group(required = false, multiple = false)]
pub struct Protocol {
    /// specify a tcp port
    #[clap(long, value_name = "TCP_PORT")]
    tcp: Option<String>,

    /// specify a udp port
    #[clap(long, value_name = "UDP_PORT")]
    udp: Option<String>,
}

pub fn update_rule(
    ctn_name: &str,
    direction: &Direction,
    _protocol: &Protocol,
    is_block: bool,
) -> Result<()> {
    // Create a folder and store the pinned maps for the container if not exist yet
    let ctn_id = get_ctn_id_from_name(&ctn_name)?;

    if is_block {
        prepare_ctn_dir(&ctn_id)?;
    }

    let ctn_dir = get_ctn_bpf_path(&ctn_id);
    let ctn_dir_path = Path::new(&ctn_dir);

    if !is_block && !ctn_dir_path.try_exists()? {
        // return if the dir doesn't exist
        println!("No rules applied to {}.", ctn_name);
        return Ok(());
    }

    let fw_map;
    let ip;

    match (&direction.to, &direction.from) {
        (Some(eg), None) => {
            // Open the pinned map for egress rules inside the container's folder
            fw_map = Map::from_pinned_path(format!("{}/{}", ctn_dir, EGRESS_MAP_NAME))?;
            ip = eg;
        }
        (None, Some(ing)) => {
            // Open the pinned map for ingress rules inside the container's folder
            fw_map = Map::from_pinned_path(format!("{}/{}", ctn_dir, INGRESS_MAP_NAME))?;
            ip = ing;
        }
        _ => unreachable!(),
    };

    // Apply the firewall rule
    let key = ipv4_to_u32(&ip)?;
    if is_block {
        let value = u8::from(true).to_ne_bytes();
        fw_map.update(&key, &value, MapFlags::ANY)?;
    } else {
        fw_map.lookup_and_delete(&key)?;
    }

    Ok(())
}

pub fn show_rules(ctn_name: &str) -> Result<()> {
    let ctn_id = get_ctn_id_from_name(&ctn_name)?;

    //use libbpf_rs::MapFlags;
    let ctn_dir = get_ctn_bpf_path(&ctn_id);

    let ctn_dir_path = Path::new(&ctn_dir);
    if !ctn_dir_path.try_exists()? {
        // return if the dir doesn't exist
        println!("No rules applied to {}.", ctn_name);
        return Ok(());
    }

    let all_maps = get_rule_maps();
    for m in all_maps {
        match m {
            EGRESS_MAP_NAME => println!("Egress (to) firewall rules: "),
            INGRESS_MAP_NAME => println!("Ingress (from) firewall rules: "),
            _ => unreachable!(),
        };
        let path = format!("{}/{}", ctn_dir, m);
        let map = Map::from_pinned_path(&path)?;

        for key in map.keys() {
            // print the key, the value is always 1 (true) here
            //let value = map.lookup(&key, MapFlags::ANY)?;
            //println!("  {:?}", value.unwrap())

            println!("  - {}", u32_to_ipv4(key)?);
        }
        println!("");
    }

    /*
    println!("[DEBUG] DATAFLOW_MAP_NAME");
    let path = format!("{}/{}", ctn_dir, DATAFLOW_MAP_NAME);
    let map = Map::from_pinned_path(&path)?;
    println!("[DEBUG] path: {:?}; type: {:?}; fd: {:?}; name: {:?}", path, map.map_type(), map.fd(), map.name());

    for key in map.keys() {
        println!("[DEBUG] found a key");
        let value = map.lookup(&key, MapFlags::ANY)?;
        println!("  {:?}", value.unwrap());
    }

    let ptr = map.as_libbpf_bpf_map_ptr();
    match ptr {
        Some(bpfmap) => println!("[DEBUG] Underlying map: {:?}", bpfmap),
        None => println!("[DEBUG] Underlying map not found !"),
    }
    */
    Ok(())
}

pub fn free_ctn_resources(ctn_name: &str) -> Result<()> {
    use std::fs::remove_dir;

    let ctn_id = get_ctn_id_from_name(&ctn_name)?;
    let ctn_dir = get_ctn_bpf_path(&ctn_id);
    let ctn_dir_path = Path::new(&ctn_dir);
    if !ctn_dir_path.try_exists()? {
        // return if the dir is already there
        //println!("[DEBUG] Dir {:?} already deleted.", ctn_dir_path);
        return Ok(());
    }

    let all_links = vec![EGRESS_LINK_NAME, INGRESS_LINK_NAME];
    let all_maps = get_all_maps();

    // if link is unpinned and map stays, the rules will not applied any more.
    for l in all_links {
        let path = format!("{}/{}", ctn_dir, l);
        let mut prog = Link::open(path)?;
        prog.unpin()?;
        println!("[DEBUG] Unpinned link {}", l);
    }

    // if map is unpinned and link stays, the rules is still in effect ?!
    for m in all_maps {
        let path = format!("{}/{}", ctn_dir, m);
        let mut map = Map::from_pinned_path(&path)?;
        map.unpin(&path)?;
        println!("[DEBUG] Unpinned map {}", m);
    }

    remove_dir(ctn_dir_path)?;

    Ok(())
}

pub fn follow(ctn_name: &str) -> Result<()> {
    let ctn_id = get_ctn_id_from_name(&ctn_name)?;
    prepare_ctn_dir(&ctn_id)?;

    let ctn_dir = get_ctn_bpf_path(&ctn_id);
    let data_flow_map = Map::from_pinned_path(format!("{}/{}", ctn_dir, DATAFLOW_MAP_NAME))?;
    let key: [u8; 0] = [];

    // receive a signal periodically
    let ticker = tick(Duration::from_millis(1000));
    // receive a signal when pressing ctrl + c
    let cancel = ctrlc_chan().unwrap();
    println!("Tracking ... press Ctrl + c to quit");

    loop {
        select! {
            recv(ticker) -> _ => {
                loop {
                    match data_flow_map.lookup_and_delete(&key) {
                        Ok(rslt) => {
                            match rslt {
                                Some(vec) => {
                                    println!("[DEBUG] dump: {:?}", vec);
                                }
                                None => {
                                    println!("[DEBUG] Empty value, should not happened !");
                                    break;
                                }
                            }
                        }
                        Err(_e) => {
                            //println!("[DEBUG] got an err: {:?}", e);
                            break;
                        }
                    }
                }
            }
            recv(cancel) -> _ => {
                println!("Ctrl-C signal caught, quit !");
                break;
            }
        }
    }

    Ok(())
}
