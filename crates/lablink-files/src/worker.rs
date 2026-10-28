//! Two fixed worker threads: browsing never waits behind a transfer. All GUI
//! messages are bounded; byte counters are coalesced in one shared snapshot.
use crate::{
    fs,
    preferences::Preferences,
    transfer::{self, record_item, Hooks, ItemResult},
    transport::{self, Connection, IdentityGuard},
    ConflictAction, Error, Job, Kind, Listing, Outcome, Progress, Result, Side,
};
use std::{
    path::PathBuf,
    sync::{
        mpsc::{self, Receiver, SyncSender, TrySendError},
        Arc, Mutex,
    },
};
use tokio::sync::oneshot;
pub use tokio_util::sync::CancellationToken;

pub type ConflictReply = oneshot::Sender<ConflictAction>;

pub enum BrowseCmd {
    List {
        generation: u64,
        device: String,
        side: Side,
        path: String,
    },
    Mkdir {
        generation: u64,
        device: String,
        side: Side,
        path: String,
        name: String,
    },
    Rename {
        generation: u64,
        device: String,
        side: Side,
        path: String,
        old: String,
        new: String,
    },
    LoadPreferences,
    SavePreferences(Preferences),
}
pub enum Event {
    Listed {
        generation: u64,
        device: String,
        side: Side,
        result: std::result::Result<Listing, String>,
    },
    Preferences(std::result::Result<Preferences, String>),
    PreferencesSaved(std::result::Result<(), String>),
    Conflict {
        id: u64,
        path: String,
        kind: Kind,
        reply: oneshot::Sender<ConflictAction>,
    },
    Finished {
        id: u64,
        result: std::result::Result<Outcome, String>,
    },
}
#[derive(Clone)]
pub struct Handle {
    pub cancel: CancellationToken,
    pub progress: Arc<Mutex<Progress>>,
    pub items: Arc<Mutex<Vec<ItemResult>>>,
}
struct Queued {
    job: Job,
    handle: Handle,
}
pub struct Worker {
    browser: SyncSender<BrowseCmd>,
    transfers: SyncSender<Queued>,
    shutdown: CancellationToken,
}
impl Worker {
    pub fn spawn(socket: PathBuf, repaint: Arc<dyn Fn() + Send + Sync>) -> (Self, Receiver<Event>) {
        let (events, rx) = mpsc::sync_channel(64);
        let (browser, commands) = mpsc::sync_channel(32);
        let (transfers, jobs) = mpsc::sync_channel::<Queued>(128);
        let shutdown = CancellationToken::new();
        {
            let (socket, events, repaint, shutdown) = (
                socket.clone(),
                events.clone(),
                repaint.clone(),
                shutdown.clone(),
            );
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Files runtime");
                for command in commands {
                    if shutdown.is_cancelled() {
                        break;
                    }
                    let event = runtime.block_on(browse(&socket, command, &shutdown));
                    repaint();
                    if events.send(event).is_err() {
                        break;
                    }
                    repaint();
                }
            });
        }
        {
            let shutdown = shutdown.clone();
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Files runtime");
                for queued in jobs {
                    if shutdown.is_cancelled() {
                        break;
                    }
                    let (id, job, handle) = (queued.job.id, queued.job, queued.handle);
                    let conflict = {
                        let events = events.clone();
                        let repaint = repaint.clone();
                        Arc::new(move |path: String, kind: Kind| {
                            let (reply, receiver) = oneshot::channel();
                            repaint();
                            let _ = events.try_send(Event::Conflict {
                                id,
                                path,
                                kind,
                                reply,
                            });
                            repaint();
                            receiver
                        })
                    };
                    let hooks = Hooks {
                        progress: handle.progress,
                        items: handle.items,
                        conflict,
                        verify: None,
                        checkpoint: None,
                    };
                    let result = runtime.block_on(async {
                        tokio::select! {
                            _ = shutdown.cancelled() => Err(Error::Cancelled),
                            result = execute_job(&socket, &job, &hooks, &handle.cancel) => result,
                        }
                    }).map_err(|e| e.user_message());
                    let result = if let Err(error) = result {
                        let mut progress = hooks.progress.lock().unwrap();
                        if progress.publication == crate::Publication::Requested {
                            progress.publication = crate::Publication::Uncertain;
                        }
                        let suffix = if progress.publication == crate::Publication::Uncertain {
                            "; publication outcome unknown, refresh destination".to_string()
                        } else if progress.files_done > 0 {
                            format!("; {} confirmed published files remain", progress.files_done)
                        } else {
                            String::new()
                        };
                        Err(format!("{error}{suffix}"))
                    } else {
                        result
                    };
                    if let Err(error) = &result {
                        let path = hooks
                            .progress
                            .lock()
                            .unwrap()
                            .current
                            .clone()
                            .unwrap_or_else(|| {
                                if job.direction == crate::Direction::Upload {
                                    job.local.display().to_string()
                                } else {
                                    job.remote.clone()
                                }
                            });
                        record_item(
                            &hooks.items,
                            ItemResult {
                                path,
                                result: error.clone(),
                            },
                        );
                    }
                    repaint();
                    if events.send(Event::Finished { id, result }).is_err() {
                        break;
                    }
                    repaint();
                }
            });
        }
        (
            Self {
                browser,
                transfers,
                shutdown,
            },
            rx,
        )
    }
    pub fn browse(&self, command: BrowseCmd) -> Result<()> {
        self.browser.try_send(command).map_err(queue_error)
    }
    pub fn enqueue(&self, job: Job) -> Result<Handle> {
        let handle = Handle {
            cancel: self.shutdown.child_token(),
            progress: Arc::new(Mutex::new(Progress {
                phase: "Queued".into(),
                ..Progress::default()
            })),
            items: Arc::new(Mutex::new(Vec::new())),
        };
        self.transfers
            .try_send(Queued {
                job,
                handle: handle.clone(),
            })
            .map_err(queue_error)?;
        Ok(handle)
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}
fn queue_error<T>(error: TrySendError<T>) -> Error {
    Error::Refused(
        match error {
            TrySendError::Full(_) => "Files queue is full; wait for pending work",
            TrySendError::Disconnected(_) => "Files worker has stopped",
        }
        .into(),
    )
}
pub async fn execute_job(
    socket: &std::path::Path,
    job: &Job,
    hooks: &Hooks,
    cancel: &CancellationToken,
) -> Result<Outcome> {
    crate::check_cancel(cancel)?;
    hooks.progress.lock().unwrap().phase = "Connecting".into();
    let guard = IdentityGuard::resolve(socket, &job.device)?;
    let connection = transport::guarded(
        Some(guard.clone()),
        cancel,
        Connection::connect(guard.target(), cancel),
    )
    .await?;
    let verified_hooks = Hooks {
        progress: hooks.progress.clone(),
        items: hooks.items.clone(),
        conflict: hooks.conflict.clone(),
        verify: Some(guard.clone()),
        checkpoint: hooks.checkpoint.clone(),
    };
    let result = transport::guarded(
        Some(guard.clone()),
        cancel,
        transfer::run(&connection, job, &verified_hooks, cancel),
    )
    .await;
    if result.is_err() {
        connection.abort();
        let mut progress = hooks.progress.lock().unwrap();
        if progress.publication == crate::Publication::Requested {
            progress.publication = crate::Publication::Uncertain;
        }
    }
    for stage in connection.stage_diagnostics() {
        record_item(
            &hooks.items,
            ItemResult {
                path: stage.path,
                result: stage.state.diagnostic().into(),
            },
        );
    }
    result
}
async fn browse(socket: &std::path::Path, command: BrowseCmd, cancel: &CancellationToken) -> Event {
    let (generation, device, side, path, operation) = match command {
        BrowseCmd::LoadPreferences => {
            return Event::Preferences(
                Preferences::load(&Preferences::path()).map_err(|e| e.user_message()),
            )
        }
        BrowseCmd::SavePreferences(preferences) => {
            return Event::PreferencesSaved(
                preferences
                    .save(&Preferences::path())
                    .map_err(|e| e.user_message()),
            )
        }
        BrowseCmd::List {
            generation,
            device,
            side,
            path,
        } => (generation, device, side, path, None),
        BrowseCmd::Mkdir {
            generation,
            device,
            side,
            path,
            name,
        } => (generation, device, side, path, Some((None, name))),
        BrowseCmd::Rename {
            generation,
            device,
            side,
            path,
            old,
            new,
        } => (generation, device, side, path, Some((Some(old), new))),
    };
    let result = async {
        if side == Side::Local {
            let local = PathBuf::from(&path);
            if let Some((old, name)) = operation {
                if let Some(old) = old {
                    fs::local_rename(&local, &old, &name)?;
                } else {
                    fs::local_mkdir(&local, &name)?;
                }
            }
            fs::local_listing(&local)
        } else {
            let guard = IdentityGuard::resolve(socket, &device)?;
            let connection = transport::guarded(
                Some(guard.clone()),
                cancel,
                Connection::connect(guard.target(), cancel),
            )
            .await?;
            transport::guarded(Some(guard), cancel, async {
                if let Some((old, name)) = operation {
                    if let Some(old) = old {
                        fs::remote_rename(&connection.sftp, &path, &old, &name).await?;
                    } else {
                        fs::remote_mkdir(&connection.sftp, &path, &name).await?;
                    }
                }
                fs::remote_listing(&connection.sftp, &path, cancel).await
            })
            .await
        }
    }
    .await
    .map_err(browse_error);
    Event::Listed {
        generation,
        device,
        side,
        result,
    }
}

fn browse_error(error: Error) -> String {
    error.user_message()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browse_status_errors_hide_hostile_server_instructions() {
        let error = Error::Sftp(russh_sftp::client::error::Error::Status(
            russh_sftp::protocol::Status {
                id: 1,
                status_code: russh_sftp::protocol::StatusCode::PermissionDenied,
                error_message: "server\u{202e}\nspoofed instructions".into(),
                language_tag: String::new(),
            },
        ));
        let text = browse_error(error);
        assert!(text.contains("permission denied"));
        assert!(!text.contains("spoofed"));
        assert!(!text.chars().any(char::is_control));
        assert!(!text.contains('\u{202e}'));
    }
}
