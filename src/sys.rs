use anyhow::{bail, Result};
use crossbeam_channel::{bounded, Receiver};
use ctrlc;
use docker_api::Docker;
use futures_util::StreamExt;
use tokio::runtime::Runtime;

pub fn increase_rlimit() -> Result<()> {
    let rl = libc::rlimit {
        rlim_cur: 1 << 20,
        rlim_max: 1 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rl) } != 0 {
        bail!("Error increasing rlimit");
    }

    Ok(())
}

/// Retrieve container's ID given its name if the container is running.
pub fn get_ctn_id_from_name(ctn_name: &str) -> Result<String> {
    use docker_api::opts::{ContainerFilter, ContainerListOpts};

    let rt = Runtime::new().unwrap();
    let docker = Docker::new("unix:///var/run/docker.sock").unwrap();

    rt.block_on(async {
        match docker
            .containers()
            .list(
                &ContainerListOpts::builder()
                    .filter(vec![ContainerFilter::Name(ctn_name.to_string())])
                    .build(),
            )
            .await
        {
            Ok(ctns) => {
                if ctns.len() < 1 {
                    bail!("Container {} not found !", ctn_name);
                }

                let ctn_id = ctns[0].id.clone().unwrap();
                Ok(ctn_id)
            }
            Err(e) => bail!("Error retrieving container {}'s ID: {}", ctn_name, e),
        }
    })
}

#[allow(dead_code)]
/// Retrieve container's network interface's index at host side
pub fn get_ctn_ifindex(ctn_id: &str) -> Result<i32> {
    use containers_api::conn::tty::TtyChunk;
    use docker_api::exec::Exec;
    use docker_api::opts::{ExecCreateOpts, ExecStartOpts};

    let rt = Runtime::new().unwrap();
    let docker = Docker::new("unix:///var/run/docker.sock").unwrap();

    rt.block_on(async {
        match Exec::create(
            docker,
            ctn_id,
            &ExecCreateOpts::builder()
                .command(["cat", "/sys/class/net/eth0/iflink"])
                .attach_stderr(true)
                .attach_stdout(true)
                .tty(true)
                .build(),
        )
        .await
        {
            Ok(ex) => match ex.start(&ExecStartOpts::builder().build()).await {
                Ok(mut mx) => {
                    let mut output: String = String::new();
                    while let Some(chunk) = mx.next().await {
                        match chunk {
                            Ok(content) => match content {
                                TtyChunk::StdOut(v) => {
                                    output.push_str(String::from_utf8_lossy(&v).trim());
                                }
                                TtyChunk::StdErr(v) => {
                                    bail!("Return from stderr: {}", String::from_utf8_lossy(&v))
                                }
                                _ => unreachable!(),
                            },
                            Err(e) => {
                                bail!("Error polling from multiplexer: {}", e)
                            }
                        }
                    }
                    output.retain(|c| c.is_ascii() && !c.is_control());
                    let rslt = output.parse::<i32>().unwrap();
                    Ok(rslt)
                }
                Err(e) => bail!("Error exec inside container: {}", e),
            },
            Err(e) => bail!("Error create exec for container: {}", e),
        }
    })
}

/// Return a recv side of a channel, will get notified when Ctrl+c is pressed
pub fn ctrlc_chan() -> Result<Receiver<()>> {
    // Creates a channel of bounded capacity
    let (sender, receiver) = bounded(10);
    ctrlc::set_handler(move || {
        let _ = sender.send(());
    })?;

    Ok(receiver)
}
