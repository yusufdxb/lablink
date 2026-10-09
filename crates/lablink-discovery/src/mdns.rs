//! Passive mDNS: browse service types and resolve `.local` names. Uses the
//! `mdns-sd` crate (one internal thread, no async runtime dependency).

use mdns_sd::{HostnameResolutionEvent, ServiceDaemon, ServiceEvent};
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// A host announced or resolved over mDNS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    /// e.g. `robot-host.local.`
    pub hostname: String,
    pub ip: IpAddr,
    pub service_type: Option<String>,
}

/// Handle to the mDNS engine. Dropping it shuts the engine down.
pub struct Mdns {
    daemon: ServiceDaemon,
}

impl Mdns {
    pub fn start() -> Result<Self, String> {
        let daemon = ServiceDaemon::new().map_err(|e| e.to_string())?;
        Ok(Self { daemon })
    }

    /// Browse `service_types`, forwarding resolved hosts to `tx` until cancelled.
    /// Returns the browse tasks' join handles (one per type).
    pub fn browse(
        &self,
        service_types: &[String],
        tx: mpsc::Sender<Sighting>,
        cancel: CancellationToken,
    ) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();
        for ty in service_types {
            let rx = match self.daemon.browse(ty) {
                Ok(rx) => rx,
                Err(e) => {
                    tracing::warn!(service_type = %ty, error = %e, "mDNS browse failed");
                    continue;
                }
            };
            let (tx, cancel, ty) = (tx.clone(), cancel.clone(), ty.clone());
            handles.push(tokio::spawn(async move {
                loop {
                    let ev = tokio::select! {
                        _ = cancel.cancelled() => break,
                        ev = rx.recv_async() => match ev { Ok(e) => e, Err(_) => break },
                    };
                    if let ServiceEvent::ServiceResolved(info) = ev {
                        for a in info.get_addresses() {
                            let s = Sighting {
                                hostname: info.get_hostname().to_string(),
                                ip: a.to_ip_addr(),
                                service_type: Some(ty.clone()),
                            };
                            // Never block the engine: drop sightings if the daemon is busy.
                            let _ = tx.try_send(s);
                        }
                    }
                }
            }));
        }
        handles
    }

    /// Resolve a `.local` hostname (with or without trailing dot).
    pub async fn resolve(&self, hostname: &str, timeout: Duration) -> Vec<IpAddr> {
        let mut name = hostname.trim().to_ascii_lowercase();
        if !name.ends_with('.') {
            name.push('.');
        }
        if !name.ends_with(".local.") {
            return Vec::new();
        }
        let rx = match self
            .daemon
            .resolve_hostname(&name, Some(timeout.as_millis() as u64))
        {
            Ok(rx) => rx,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        let _ = tokio::time::timeout(timeout + Duration::from_millis(200), async {
            while let Ok(ev) = rx.recv_async().await {
                match ev {
                    HostnameResolutionEvent::AddressesFound(_, addrs) => {
                        out.extend(addrs.iter().map(|a| a.to_ip_addr()));
                        break;
                    }
                    HostnameResolutionEvent::SearchTimeout(_)
                    | HostnameResolutionEvent::SearchStopped(_) => break,
                    _ => {}
                }
            }
        })
        .await;
        let _ = self.daemon.stop_resolve_hostname(&name);
        out.sort();
        out.dedup();
        out
    }
}

impl Drop for Mdns {
    fn drop(&mut self) {
        let _ = self.daemon.shutdown();
    }
}
