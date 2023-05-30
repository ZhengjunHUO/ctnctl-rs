use anyhow::{bail, Result};
use crossbeam_channel::{bounded, Receiver};
use ctrlc;

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

pub fn get_ctn_id_from_name(ctn_name: &str) -> Result<String> {
    use docker_api::opts::{ContainerFilter, ContainerListOpts};
    use docker_api::Docker;
    use tokio::runtime::Runtime;

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

pub fn ctrlc_chan() -> Result<Receiver<()>> {
    // Creates a channel of bounded capacity
    let (sender, receiver) = bounded(10);
    ctrlc::set_handler(move || {
        let _ = sender.send(());
    })?;

    Ok(receiver)
}
