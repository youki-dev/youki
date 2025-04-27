use std::fs::File;
use std::os::fd::BorrowedFd;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::thread;

use futures::stream::TryStreamExt;
use netlink_packet_route::address::{AddressAttribute, AddressFlags, AddressScope};
use nix::sched::{setns, CloneFlags};
use oci_spec::runtime::LinuxNetDevice;
use rtnetlink::{new_connection, LinkUnspec};

type Result<T> = std::result::Result<T, NetworkError>;

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error(transparent)]
    Rtnetlink(#[from] rtnetlink::Error),
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    IO(#[from] std::io::Error),
}

/// dev_change_netns allows to move a device given by name to a network namespace given by nsPath
/// and optionally change the device name.
/// The device name will be kept the same if device.Name is the zero value.
/// This function ensures that the move and rename operations occur atomically.
/// It preserves existing interface attributes, including IP addresses.
pub async fn dev_change_net_namespace(
    name: String,
    netns_path: String,
    device: LinuxNetDevice,
) -> Result<()> {
    tracing::debug!(
        "attaching network device {} to network namespace {}",
        name,
        netns_path
    );
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let netns_file = File::open(netns_path)?;
    let origin_netns_file = File::open("/proc/self/ns/net")?;

    let origin_netns_file = Arc::new(origin_netns_file);
    let netns_file = Arc::new(netns_file);

    let netns_fd = netns_file.as_raw_fd();
    let origin_netns_fd = origin_netns_file.as_raw_fd();

    let mut links = handle.link().get().match_name(name.clone()).execute();

    let new_name = device
        .name()
        .as_ref()
        .filter(|d| !d.is_empty())
        .map_or(name.clone(), |d| d.to_string());

    let mut addr_vec = Vec::new();
    if let Some(link) = links.try_next().await? {
        // Set the interface link state to DOWN before modifying attributes like namespace or name.
        // This prevents potential conflicts or disruptions on the host network during the transition,
        // particularly if other host components depend on this specific interface or its properties.
        handle
            .link()
            .set(LinkUnspec::new_with_index(link.header.index).down().build())
            .execute()
            .await?;

        // Get the existing IP addresses on the interface.
        let mut address = handle
            .address()
            .get()
            .set_link_index_filter(link.header.index)
            .execute();

        while let Some(addr) = address.try_next().await? {
            tracing::debug!("address: {:#?}", addr);
            addr_vec.push(addr);
        }

        let set_req_builder = LinkUnspec::new_with_index(link.header.index);

        let req = set_req_builder
            .name(new_name.clone())
            .setns_by_fd(netns_fd)
            .build();

        handle.link().set(req).execute().await?;
    }

    let borrowed_netns_fd = unsafe { BorrowedFd::borrow_raw(netns_fd) };
    let borrowed_origin_netns_fd = unsafe { BorrowedFd::borrow_raw(origin_netns_fd) };

    thread::spawn(move || -> Result<()> {
        setns(borrowed_netns_fd, CloneFlags::CLONE_NEWNET)?;

        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let (connection, handle, _) = new_connection()?;
            tokio::spawn(connection);

            let mut links = handle.link().get().match_name(new_name.clone()).execute();
            let link = match links.try_next().await? {
                Some(link) => link,
                None => {
                    tracing::error!("network device {} is not present", new_name);
                    return Err(NetworkError::IO(std::io::Error::from(
                        std::io::ErrorKind::NotFound,
                    )));
                }
            };
            // Re-add the original IP addresses to the interface in the new namespace.
            // The kernel removes IP addresses when an interface is moved between network namespaces.
            for addr in addr_vec {
                tracing::debug!(
                    "processing address {:?} from network device {}",
                    addr.clone(),
                    name
                );
                let mut ip_opts = None;
                let mut flags_opts = None;
                // Only move IP addresses with global scope because those are not host-specific, auto-configured,
                // or have limited network scope, making them unsuitable inside the container namespace.
                // Ref: https://www.ietf.org/rfc/rfc3549.txt
                if addr.header.scope != AddressScope::Universe {
                    tracing::debug!(
                        "skipping address {:?} from network device {}",
                        addr.clone(),
                        name
                    );
                    continue;
                }
                for attr in &addr.attributes {
                    match attr {
                        AddressAttribute::Flags(flags) => flags_opts = Some(*flags),
                        AddressAttribute::Address(ip) => ip_opts = Some(*ip),
                        _ => {}
                    }
                }

                // Only move permanent IP addresses configured by the user, dynamic addresses are excluded because
                // their validity may rely on the original network namespace's context and they may have limited
                // lifetimes and are not guaranteed to be available in a new namespace.
                // Ref: https://www.ietf.org/rfc/rfc3549.txt
                if let Some(flag) = flags_opts {
                    if !flag.contains(AddressFlags::Permanent) {
                        tracing::debug!(
                            "skipping address {:?} from network device {}",
                            addr.clone(),
                            name
                        );
                        continue;
                    }
                }
                if let Some(ip) = ip_opts {
                    // Remove the interface attribute of the original address
                    // to avoid issues when the interface is renamed.
                    handle
                        .address()
                        .add(link.header.index, ip, addr.header.prefix_len)
                        .execute()
                        .await?
                }
            }

            handle
                .link()
                .set(LinkUnspec::new_with_index(link.header.index).up().build())
                .execute()
                .await?;

            Ok(())
        })?;

        setns(borrowed_origin_netns_fd, CloneFlags::CLONE_NEWNET)?;

        Ok(())
    })
    .join()
    .expect("failed to join thread")?;

    Ok(())
}
