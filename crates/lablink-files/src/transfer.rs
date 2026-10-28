use crate::staging::{same_inode, LocalLease, LocalStage};
use crate::transport::{Connection, RemoteStageState};
use crate::{
    check_cancel, fs, remote_join, validate_name, ConflictAction, Direction, Error, Job, Kind,
    Outcome, Progress, Publication, Result,
};
use cap_fs_ext::DirExt;
use cap_std::fs::Dir;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

pub type ConflictCallback =
    Arc<dyn Fn(String, Kind) -> oneshot::Receiver<ConflictAction> + Send + Sync>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Boundary {
    SourceDirectoryOpening,
    RemoteSourceOpening,
    RemoteSourceOpened,
    DestinationDirectoryOpening,
    StagePlanned,
    StageCreated,
    ChunkWritten,
    Copied,
    BeforePublish,
    RemoteStageVerified,
    Published,
}
#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub boundary: Boundary,
    pub path: String,
    pub staging: Option<String>,
    pub bytes: u64,
}
pub type CheckpointCallback = Arc<dyn Fn(Checkpoint) -> Result<()> + Send + Sync>;

pub struct Hooks {
    pub progress: Arc<Mutex<Progress>>,
    pub items: Arc<Mutex<Vec<ItemResult>>>,
    pub conflict: ConflictCallback,
    pub verify: Option<crate::transport::IdentityGuard>,
    /// Deterministic fault scheduling for transport/filesystem adversarial tests.
    pub checkpoint: Option<CheckpointCallback>,
}
#[derive(Clone, Debug)]
pub struct ItemResult {
    pub path: String,
    pub result: String,
}

/// Queue rows persist after completion; tree limits alone do not bound their
/// accumulated diagnostics across hundreds of retained jobs.
pub const MAX_ITEM_RESULTS: usize = 256;
const MAX_DIAGNOSTIC_BYTES: usize = 4096;

pub(crate) fn record_item(items: &Mutex<Vec<ItemResult>>, mut item: ItemResult) {
    for text in [&mut item.path, &mut item.result] {
        if text.len() > MAX_DIAGNOSTIC_BYTES {
            let suffix = " [diagnostic truncated]";
            let mut end = MAX_DIAGNOSTIC_BYTES - suffix.len();
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push_str(suffix);
        }
        // The input may originate in a large SFTP error packet. Do not keep its
        // original allocation after truncating the displayed text.
        text.shrink_to_fit();
    }
    let mut items = items.lock().unwrap();
    if items.len() < MAX_ITEM_RESULTS {
        items.push(item);
    } else {
        items[MAX_ITEM_RESULTS - 2] = ItemResult {
            path: String::new(),
            result: "Further individual results omitted; counts remain exact. Remote staging paths may be omitted. Inspect the destination before recovery; never delete by prefix.".into(),
        };
        items[MAX_ITEM_RESULTS - 1] = item;
    }
}

struct Node {
    name: String,
    kind: Kind,
    attrs: FileAttributes,
    local_parent: Option<Arc<Dir>>,
    local_snapshot: Option<cap_std::fs::Metadata>,
    remote_path: String,
    children: Vec<Node>,
}
fn local_plan(
    parent: Arc<Dir>,
    name: String,
    depth: usize,
    count: &mut usize,
    total: &mut u64,
    cancel: &CancellationToken,
    hooks: &Hooks,
) -> Result<Node> {
    check_cancel(cancel)?;
    validate_name(&name)?;
    *count += 1;
    if *count > fs::MAX_ENTRIES || depth > fs::MAX_DEPTH {
        return Err(Error::Refused("Transfer exceeds tree safety limits".into()));
    }
    let m = parent.symlink_metadata(&name)?;
    let kind = if fs::is_staging_name(&name) {
        Kind::Other
    } else if m.is_symlink() {
        Kind::Symlink
    } else if m.is_dir() {
        Kind::Directory
    } else if m.is_file() {
        Kind::File
    } else {
        Kind::Other
    };
    let attrs = FileAttributes {
        size: Some(m.len()),
        mtime: m
            .modified()
            .ok()
            .and_then(|t| t.into_std().duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|d| u32::try_from(d.as_secs()).ok()),
        ..FileAttributes::empty()
    };
    let mut node = Node {
        name: name.clone(),
        kind,
        attrs,
        local_parent: Some(parent.clone()),
        local_snapshot: Some(m.clone()),
        remote_path: String::new(),
        children: Vec::new(),
    };
    if kind == Kind::Directory {
        if let Some(callback) = &hooks.checkpoint {
            callback(Checkpoint {
                boundary: Boundary::SourceDirectoryOpening,
                path: name.clone(),
                staging: None,
                bytes: 0,
            })?;
        }
        let dir = Arc::new(parent.open_dir_nofollow(&name)?);
        if !same_inode(&m, &dir.dir_metadata()?) {
            return Err(Error::Refused(
                "Source directory substituted while opening".into(),
            ));
        }
        for e in dir.entries()? {
            let child = e?
                .file_name()
                .into_string()
                .map_err(|_| Error::Refused("Non-UTF-8 filenames are unsupported".into()))?;
            node.children.push(local_plan(
                dir.clone(),
                child,
                depth + 1,
                count,
                total,
                cancel,
                hooks,
            )?);
        }
    } else if kind == Kind::File {
        *total = total
            .checked_add(m.len())
            .ok_or_else(|| Error::Refused("Transfer size overflow".into()))?;
    }
    Ok(node)
}
fn remote_plan<'a>(
    connection: &'a Connection,
    path: String,
    depth: usize,
    count: &'a mut usize,
    total: &'a mut u64,
    cancel: &'a CancellationToken,
) -> Pin<Box<dyn Future<Output = Result<Node>> + 'a>> {
    Box::pin(async move {
        check_cancel(cancel)?;
        *count += 1;
        if *count > fs::MAX_ENTRIES || depth > fs::MAX_DEPTH {
            return Err(Error::Refused("Transfer exceeds tree safety limits".into()));
        }
        let name = path.rsplit('/').next().unwrap_or_default().to_string();
        validate_name(&name)?;
        let attrs = connection.sftp.lstat(path.clone()).await?.attrs;
        let kind = if fs::is_staging_name(&name) {
            Kind::Other
        } else {
            fs::remote_kind(&attrs)
        };
        let mut node = Node {
            name,
            kind,
            attrs,
            local_parent: None,
            local_snapshot: None,
            remote_path: path.clone(),
            children: Vec::new(),
        };
        if kind == Kind::Directory {
            for entry in fs::remote_listing(&connection.sftp, &path, cancel)
                .await?
                .entries
            {
                node.children.push(
                    remote_plan(
                        connection,
                        remote_join(&path, &entry.name)?,
                        depth + 1,
                        count,
                        total,
                        cancel,
                    )
                    .await?,
                );
            }
        } else if kind == Kind::File {
            let size = node
                .attrs
                .size
                .ok_or_else(|| Error::Refused("Server did not report file size".into()))?;
            *total = total
                .checked_add(size)
                .ok_or_else(|| Error::Refused("Transfer size overflow".into()))?;
        }
        Ok(node)
    })
}
fn files_count(node: &Node) -> usize {
    usize::from(node.kind == Kind::File) + node.children.iter().map(files_count).sum::<usize>()
}
fn same_remote(a: &FileAttributes, b: &FileAttributes) -> bool {
    a.size == b.size
        && a.mtime == b.mtime
        && a.permissions == b.permissions
        && a.uid == b.uid
        && a.gid == b.gid
}
fn copy_name(name: &str, n: usize) -> Result<String> {
    let suffix = format!(" (copy {n})");
    let extension = Path::new(name)
        .extension()
        .and_then(|s| s.to_str())
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    let stem = name.strip_suffix(&extension).unwrap_or(name);
    let mut stem = stem.to_owned();
    while stem.len() + suffix.len() + extension.len() > 255 {
        if stem.pop().is_none() {
            return Err(Error::Refused(
                "Cannot generate a safe collision name".into(),
            ));
        }
    }
    let generated = format!("{stem}{suffix}{extension}");
    validate_name(&generated)?;
    Ok(generated)
}

/// Last measured payload rate, sampled at most five times per second. Keeping
/// only a timestamp and byte count bounds memory independently of file size.
struct PayloadRate {
    sampled_at: Instant,
    sampled_bytes: u64,
    bytes_per_second: f64,
}
impl PayloadRate {
    fn new(now: Instant) -> Self {
        Self {
            sampled_at: now,
            sampled_bytes: 0,
            bytes_per_second: 0.0,
        }
    }
    fn update(&mut self, bytes: u64, active: bool, now: Instant) -> f64 {
        if !active {
            self.sampled_at = now;
            self.sampled_bytes = bytes;
            self.bytes_per_second = 0.0;
            return 0.0;
        }
        let elapsed = now.duration_since(self.sampled_at);
        if elapsed >= Duration::from_millis(200) {
            self.bytes_per_second =
                bytes.saturating_sub(self.sampled_bytes) as f64 / elapsed.as_secs_f64();
            self.sampled_at = now;
            self.sampled_bytes = bytes;
        }
        self.bytes_per_second
    }
}

struct Engine<'a> {
    connection: &'a Connection,
    hooks: &'a Hooks,
    cancel: &'a CancellationToken,
    rate: PayloadRate,
    progress: Progress,
}
impl Engine<'_> {
    fn checkpoint(&self, boundary: Boundary, path: &str, staging: Option<&str>) -> Result<()> {
        if let Some(callback) = &self.hooks.checkpoint {
            callback(Checkpoint {
                boundary,
                path: path.into(),
                staging: staging.map(str::to_owned),
                bytes: self.progress.bytes,
            })?;
        }
        Ok(())
    }
    fn verify(&self) -> Result<()> {
        check_cancel(self.cancel)?;
        if let Some(guard) = &self.hooks.verify {
            guard.check()?;
        }
        Ok(())
    }
    fn publish(&mut self, phase: impl Into<String>) {
        self.progress.phase = phase.into();
        // Verification does not move payload bytes. Do not reuse an active
        // copy's speed for verification, conflict waits or publication.
        self.progress.bytes_per_second = self.rate.update(
            self.progress.bytes,
            matches!(self.progress.phase.as_str(), "Uploading" | "Downloading"),
            Instant::now(),
        );
        *self.hooks.progress.lock().unwrap() = self.progress.clone();
    }
    async fn decide(&mut self, path: &str, kind: Kind) -> Result<ConflictAction> {
        self.progress.current = Some(path.to_owned());
        self.publish("Waiting for conflict decision");
        let decision = (self.hooks.conflict)(path.to_string(), kind);
        tokio::select! {
            _ = self.cancel.cancelled() => Err(Error::Cancelled),
            result = decision => result.map_err(|_| if self.cancel.is_cancelled() {Error::Cancelled} else {Error::Refused("Conflict decision channel closed or queue full; transfer refused".into())}),
        }
    }
    fn skip(&mut self, node: &Node, path: &str, reason: &str) {
        self.progress.skipped += 1;
        record_item(
            &self.hooks.items,
            ItemResult {
                path: path.into(),
                result: reason.into(),
            },
        );
        self.progress.total = self.progress.total.saturating_sub(node_size(node));
        self.progress.files_total = self.progress.files_total.saturating_sub(files_count(node));
        self.publish(reason);
    }
    fn upload_node<'a>(
        &'a mut self,
        node: &'a Node,
        parent: String,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
        Box::pin(async move {
            check_cancel(self.cancel)?;
            fs::remote_dir(&self.connection.sftp, &parent).await?;
            let mut dest = remote_join(&parent, &node.name)?;
            self.progress.current = Some(dest.clone());
            self.publish("Preparing item");
            if matches!(node.kind, Kind::Symlink | Kind::Other) {
                self.skip(
                    node,
                    &dest,
                    if fs::is_staging_name(&node.name) {
                        "Skipped reserved staging namespace (ownership not assumed)"
                    } else {
                        "Skipped symlink or special file"
                    },
                );
                return Ok(());
            }
            let mut existing = fs::remote_metadata(&self.connection.sftp, &dest).await?;
            if let Some(ref attrs) = existing {
                match self.decide(&dest, node.kind).await? {
                    ConflictAction::Skip => {
                        self.skip(node, &dest, "Skipped destination conflict");
                        return Ok(());
                    }
                    ConflictAction::Replace => {
                        self.verify()?;
                        if node.kind == Kind::File {
                            return Err(Error::Refused("File Replace refused: SFTP has no atomic compare-and-swap; use Skip or Keep Both".into()));
                        }
                        if fs::remote_kind(attrs) != node.kind {
                            return Err(Error::Refused("Replace requires matching file/folder types; symlinks cannot be replaced".into()));
                        }
                    }
                    ConflictAction::KeepBoth => {
                        let mut found = false;
                        for n in 1..10_000 {
                            dest = remote_join(&parent, &copy_name(&node.name, n)?)?;
                            if fs::remote_metadata(&self.connection.sftp, &dest)
                                .await?
                                .is_none()
                            {
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            return Err(Error::Refused("No available Keep Both name".into()));
                        }
                        existing = None;
                    }
                }
            }
            self.verify()?;
            // Conflict decisions may park this operation indefinitely. Check
            // ancestors again before creating any remote object or staging.
            fs::remote_dir(&self.connection.sftp, &parent).await?;
            self.verify()?;
            if node.kind == Kind::Directory {
                if existing.is_none() {
                    self.connection
                        .sftp
                        .mkdir(
                            dest.clone(),
                            FileAttributes {
                                permissions: Some(0o700),
                                ..FileAttributes::empty()
                            },
                        )
                        .await?;
                }
                for child in &node.children {
                    self.upload_node(child, dest.clone()).await?;
                }
                record_item(
                    &self.hooks.items,
                    ItemResult {
                        path: dest,
                        result: "Folder complete".into(),
                    },
                );
                return Ok(());
            }
            self.upload_file(node, &dest, existing.as_ref()).await
        })
    }
    async fn upload_file(
        &mut self,
        node: &Node,
        dest: &str,
        existing: Option<&FileAttributes>,
    ) -> Result<()> {
        if existing.is_some() {
            return Err(Error::Refused(
                "File Replace requires atomic compare-and-swap and is refused".into(),
            ));
        }
        if !self.connection.hardlink || !self.connection.fsync {
            return Err(Error::Refused("Server lacks safe publication (hardlink and fsync extensions); upload refused without a rename fallback".into()));
        }
        let mut source = fs::local_open(node.local_parent.as_ref().unwrap(), &node.name, false)?;
        let before = source.metadata()?;
        if !same_local(&before, node.local_snapshot.as_ref().unwrap()) {
            return Err(Error::Refused(
                "Source changed during transfer planning".into(),
            ));
        }
        let parent = crate::remote_parent(dest);
        let temporary = remote_join(
            parent,
            &format!(".lablink-transfer-{}", uuid::Uuid::new_v4()),
        )?;
        self.checkpoint(Boundary::StagePlanned, dest, Some(&temporary))?;
        self.verify()?;
        fs::remote_dir(&self.connection.sftp, parent).await?;
        self.verify()?;
        self.connection.plan_stage(&temporary);
        let handle = self
            .connection
            .sftp
            .open(
                temporary.clone(),
                OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
                FileAttributes {
                    permissions: Some(0o600),
                    ..FileAttributes::empty()
                },
            )
            .await?
            .handle;
        self.connection
            .stage_state(&temporary, RemoteStageState::Created);
        self.progress.publication = Publication::NotRequested;
        self.checkpoint(Boundary::StageCreated, dest, Some(&temporary))?;
        self.verify()?;
        fs::remote_dir(&self.connection.sftp, parent).await?;
        self.verify()?;
        self.publish("Uploading");
        let mut offset = 0;
        let mut hash = Sha256::new();
        let mut buf = [0u8; 32 * 1024];
        loop {
            self.verify()?;
            let n = source.read(&mut buf)?;
            if n == 0 {
                break;
            }
            if offset + n as u64 > before.len() {
                return Err(Error::Refused("Source grew during transfer".into()));
            }
            self.verify()?;
            self.connection
                .sftp
                .write(handle.clone(), offset, buf[..n].to_vec())
                .await?;
            hash.update(&buf[..n]);
            offset += n as u64;
            self.progress.bytes += n as u64;
            self.publish("Uploading");
            self.checkpoint(Boundary::ChunkWritten, dest, Some(&temporary))?;
        }
        self.checkpoint(Boundary::Copied, dest, Some(&temporary))?;
        self.publish("Verifying local source");
        if offset != before.len() || !same_local(&before, &source.metadata()?) {
            return Err(Error::Refused("Source changed during transfer".into()));
        }
        let expected = hash.finalize().to_vec();
        source.seek(SeekFrom::Start(0))?;
        let mut reread = Sha256::new();
        let mut checked = 0;
        loop {
            self.verify()?;
            let n = source.read(&mut buf)?;
            if n == 0 {
                break;
            }
            checked += n as u64;
            if checked > offset {
                return Err(Error::Refused("Source grew during verification".into()));
            }
            reread.update(&buf[..n]);
        }
        if checked != offset
            || reread.finalize().as_slice() != expected
            || !same_local(&before, &source.metadata()?)
        {
            return Err(Error::Refused(
                "Source content changed during transfer verification".into(),
            ));
        }
        self.verify()?;
        self.publish("Synchronizing remote destination");
        self.connection.sftp.fsync(handle.clone()).await?;
        self.verify()?;
        self.publish("Verifying remote destination");
        let staged = self.connection.sftp.fstat(handle.clone()).await?.attrs;
        if fs::remote_kind(&staged) != Kind::File || staged.size != Some(offset) {
            return Err(Error::Refused("Invalid remote staging metadata".into()));
        }
        // Verify bytes on the held handle, not by reopening an arbitrary path.
        let mut copied = Sha256::new();
        let mut checked = 0;
        while checked < offset {
            self.verify()?;
            let length = (offset - checked).min(32 * 1024) as u32;
            let bytes = self
                .connection
                .sftp
                .read(handle.clone(), checked, length)
                .await?
                .data;
            if bytes.is_empty() || bytes.len() > length as usize {
                return Err(Error::Refused("Invalid remote staging data".into()));
            }
            copied.update(&bytes);
            checked += bytes.len() as u64;
        }
        if copied.finalize().as_slice() != expected {
            return Err(Error::Refused(
                "Remote staging content changed; publication refused".into(),
            ));
        }
        self.checkpoint(Boundary::BeforePublish, dest, Some(&temporary))?;
        self.verify()?;
        fs::remote_dir(&self.connection.sftp, parent).await?;
        self.verify()?;
        let entry = self.connection.sftp.lstat(temporary.clone()).await?.attrs;
        if fs::remote_kind(&entry) != Kind::File || !same_remote(&staged, &entry) {
            return Err(Error::Refused(
                "Remote staging substituted; publication refused".into(),
            ));
        }
        // SFTP metadata has no inode identity. A regular-file substitute can
        // preserve size, permissions and second-resolution mtime. Validate the
        // publication pathname's content too, separately from the held handle.
        // This detects persistent substitution, not a swap after this check.
        self.publish("Verifying remote destination pathname");
        self.verify()?;
        let named = self
            .connection
            .sftp
            .open(temporary.clone(), OpenFlags::READ, FileAttributes::empty())
            .await?
            .handle;
        self.verify()?;
        let opened = self.connection.sftp.fstat(named.clone()).await?.attrs;
        if fs::remote_kind(&opened) != Kind::File || !same_remote(&staged, &opened) {
            return Err(Error::Refused(
                "Remote staging pathname changed while verifying".into(),
            ));
        }
        let mut named_hash = Sha256::new();
        let mut checked = 0;
        while checked < offset {
            self.verify()?;
            let length = (offset - checked).min(32 * 1024) as u32;
            let bytes = self
                .connection
                .sftp
                .read(named.clone(), checked, length)
                .await?
                .data;
            if bytes.is_empty() || bytes.len() > length as usize {
                return Err(Error::Refused("Invalid staging pathname data".into()));
            }
            named_hash.update(&bytes);
            checked += bytes.len() as u64;
        }
        self.verify()?;
        let after = self.connection.sftp.fstat(named.clone()).await?.attrs;
        if !same_remote(&staged, &after) || named_hash.finalize().as_slice() != expected {
            return Err(Error::Refused(
                "Remote staging pathname content changed; publication refused".into(),
            ));
        }
        self.verify()?;
        self.connection.sftp.close(named).await?;
        self.checkpoint(Boundary::RemoteStageVerified, dest, Some(&temporary))?;
        self.verify()?;
        fs::remote_dir(&self.connection.sftp, parent).await?;
        self.verify()?;
        let entry = self.connection.sftp.lstat(temporary.clone()).await?.attrs;
        if fs::remote_kind(&entry) != Kind::File || !same_remote(&staged, &entry) {
            return Err(Error::Refused(
                "Remote staging substituted before publication".into(),
            ));
        }
        self.verify()?;
        self.progress.publication = Publication::Requested;
        self.connection
            .stage_state(&temporary, RemoteStageState::PublicationRequested);
        self.publish("Publishing; interruption can leave outcome uncertain");
        let result = self
            .connection
            .sftp
            .hardlink(temporary.clone(), dest.to_owned())
            .await;
        if let Err(error) = result {
            // Errors do not prove a remote/network filesystem did not commit.
            self.progress.publication = Publication::Uncertain;
            self.connection
                .stage_state(&temporary, RemoteStageState::PublicationUncertain);
            self.publish("Publication failed; staging retained");
            return Err(error.into());
        }
        self.progress.publication = Publication::Confirmed;
        self.connection
            .stage_state(&temporary, RemoteStageState::Published);
        self.progress.files_done += 1;
        record_item(
            &self.hooks.items,
            ItemResult {
                path: dest.into(),
                result: format!("Uploaded; private staging retained: {temporary}"),
            },
        );
        self.publish("Finalizing upload");
        self.checkpoint(Boundary::Published, dest, Some(&temporary))?;
        self.verify()?;
        self.connection.sftp.close(handle).await?;
        Ok(())
    }
    fn download_node<'a>(
        &'a mut self,
        node: &'a Node,
        parent: Arc<Dir>,
        display: String,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
        Box::pin(async move {
            self.verify()?;
            let _lease = LocalLease::acquire(&parent)?;
            let mut name = node.name.clone();
            self.progress.current = Some(format!("{display}/{name}"));
            self.publish("Preparing item");
            if matches!(node.kind, Kind::Symlink | Kind::Other) {
                self.skip(
                    node,
                    &node.remote_path,
                    if fs::is_staging_name(&node.name) {
                        "Skipped reserved staging namespace (ownership not assumed)"
                    } else {
                        "Skipped symlink or special file"
                    },
                );
                return Ok(());
            }
            let mut existing = match parent.symlink_metadata(&name) {
                Ok(m) => Some(m),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e.into()),
            };
            if let Some(ref attrs) = existing {
                match self.decide(&format!("{display}/{name}"), node.kind).await? {
                    ConflictAction::Skip => {
                        self.skip(node, &node.remote_path, "Skipped destination conflict");
                        return Ok(());
                    }
                    ConflictAction::Replace => {
                        self.verify()?;
                        if node.kind == Kind::File {
                            return Err(Error::Refused("File Replace refused: local rename cannot atomically compare an existing destination; use Skip or Keep Both".into()));
                        }
                        if attrs.is_symlink()
                            || (node.kind == Kind::File && !attrs.is_file())
                            || (node.kind == Kind::Directory && !attrs.is_dir())
                        {
                            return Err(Error::Refused("Replace requires matching file/folder types; symlinks cannot be replaced".into()));
                        }
                    }
                    ConflictAction::KeepBoth => {
                        let mut found = false;
                        for n in 1..10_000 {
                            name = copy_name(&node.name, n)?;
                            match parent.symlink_metadata(&name) {
                                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                    found = true;
                                    break;
                                }
                                Err(e) => return Err(e.into()),
                                Ok(_) => (),
                            }
                        }
                        if !found {
                            return Err(Error::Refused("No available Keep Both name".into()));
                        }
                        existing = None;
                    }
                }
            }
            self.verify()?;
            if node.kind == Kind::Directory {
                if existing.is_none() {
                    parent.create_dir(&name)?;
                    existing = Some(parent.symlink_metadata(&name)?);
                }
                self.checkpoint(
                    Boundary::DestinationDirectoryOpening,
                    &format!("{display}/{name}"),
                    None,
                )?;
                self.verify()?;
                let dir = Arc::new(parent.open_dir_nofollow(&name)?);
                let opened = dir.dir_metadata()?;
                if existing.as_ref().is_some_and(|m| !same_inode(m, &opened)) {
                    return Err(Error::Refused(
                        "Destination directory substituted while opening".into(),
                    ));
                }
                for child in &node.children {
                    self.download_node(child, dir.clone(), format!("{display}/{name}"))
                        .await?;
                }
                record_item(
                    &self.hooks.items,
                    ItemResult {
                        path: format!("{display}/{name}"),
                        result: "Folder complete".into(),
                    },
                );
                return Ok(());
            }
            self.download_file(node, &parent, &name, existing.as_ref())
                .await
        })
    }
    async fn download_file(
        &mut self,
        node: &Node,
        parent: &Dir,
        name: &str,
        existing: Option<&cap_std::fs::Metadata>,
    ) -> Result<()> {
        if existing.is_some() {
            return Err(Error::Refused(
                "File Replace requires atomic compare-and-swap and is refused".into(),
            ));
        }
        self.verify()?;
        fs::remote_dir(
            &self.connection.sftp,
            crate::remote_parent(&node.remote_path),
        )
        .await?;
        self.verify()?;
        let attrs = self
            .connection
            .sftp
            .lstat(node.remote_path.clone())
            .await?
            .attrs;
        if fs::remote_kind(&attrs) != Kind::File || !same_remote(&attrs, &node.attrs) {
            return Err(Error::Refused(
                "Remote source changed since planning".into(),
            ));
        }
        self.verify()?;
        self.checkpoint(Boundary::RemoteSourceOpening, &node.remote_path, None)?;
        self.verify()?;
        let handle = self
            .connection
            .sftp
            .open(
                node.remote_path.clone(),
                OpenFlags::READ,
                FileAttributes::empty(),
            )
            .await?
            .handle;
        self.verify()?;
        self.checkpoint(Boundary::RemoteSourceOpened, &node.remote_path, None)?;
        self.verify()?;
        fs::remote_dir(
            &self.connection.sftp,
            crate::remote_parent(&node.remote_path),
        )
        .await?;
        self.verify()?;
        let leaf = self
            .connection
            .sftp
            .lstat(node.remote_path.clone())
            .await?
            .attrs;
        if fs::remote_kind(&leaf) != Kind::File || !same_remote(&attrs, &leaf) {
            return Err(Error::Refused(
                "Remote source pathname substituted while opening".into(),
            ));
        }
        self.verify()?;
        let opened = self.connection.sftp.fstat(handle.clone()).await?.attrs;
        if !same_remote(&attrs, &opened) {
            return Err(Error::Refused("Remote source changed while opening".into()));
        }
        let mut stage = LocalStage::create(parent)?;
        let items = self.hooks.items.clone();
        stage.set_cleanup_reporter(Arc::new(move |path, message| {
            record_item(
                &items,
                ItemResult {
                    path,
                    result: message,
                },
            );
        }));
        let temporary = stage.name().to_owned();
        self.progress.publication = Publication::NotRequested;
        self.checkpoint(Boundary::StageCreated, &node.remote_path, Some(&temporary))?;
        self.publish("Downloading");
        let size = node.attrs.size.unwrap();
        let mut offset = 0;
        let mut copied = Sha256::new();
        while offset < size {
            self.verify()?;
            let length = (size - offset).min(32 * 1024) as u32;
            let data = self
                .connection
                .sftp
                .read(handle.clone(), offset, length)
                .await?
                .data;
            if data.is_empty() || data.len() > length as usize {
                return Err(Error::Refused(
                    "Server returned invalid file data length".into(),
                ));
            }
            stage.file.write_all(&data)?;
            copied.update(&data);
            offset += data.len() as u64;
            self.progress.bytes += data.len() as u64;
            self.publish("Downloading");
            self.checkpoint(Boundary::ChunkWritten, &node.remote_path, Some(&temporary))?;
        }
        self.checkpoint(Boundary::Copied, &node.remote_path, Some(&temporary))?;
        self.publish("Verifying remote source");
        // A second bounded pass detects persisted same-size, same-mtime edits.
        let mut checked = 0;
        let mut reread = Sha256::new();
        while checked < size {
            self.verify()?;
            let length = (size - checked).min(32 * 1024) as u32;
            let bytes = self
                .connection
                .sftp
                .read(handle.clone(), checked, length)
                .await?
                .data;
            if bytes.is_empty() || bytes.len() > length as usize {
                return Err(Error::Refused("Invalid source verification data".into()));
            }
            reread.update(&bytes);
            checked += bytes.len() as u64;
        }
        self.verify()?;
        let after = self.connection.sftp.fstat(handle.clone()).await?.attrs;
        let expected = copied.finalize();
        if !same_remote(&attrs, &after) || expected != reread.finalize() {
            return Err(Error::Refused(
                "Remote source content changed during transfer".into(),
            ));
        }
        self.verify()?;
        self.connection.sftp.close(handle).await?;
        self.publish("Synchronizing local destination");
        stage.file.sync_all()?;
        let staged = stage.file.metadata()?;
        self.checkpoint(Boundary::BeforePublish, &node.remote_path, Some(&temporary))?;
        self.publish("Verifying local destination");
        self.verify()?;
        stage.verify()?;
        stage.file.seek(SeekFrom::Start(0))?;
        let mut staged_hash = Sha256::new();
        let mut checked = 0;
        let mut buffer = [0u8; 32 * 1024];
        loop {
            self.verify()?;
            let length = stage.file.read(&mut buffer)?;
            if length == 0 {
                break;
            }
            checked += length as u64;
            if checked > size {
                return Err(Error::Refused(
                    "Local staging grew before publication".into(),
                ));
            }
            staged_hash.update(&buffer[..length]);
        }
        if checked != size
            || staged_hash.finalize() != expected
            || !same_local(&staged, &stage.file.metadata()?)
        {
            return Err(Error::Refused(
                "Local staging content changed; publication refused".into(),
            ));
        }
        self.verify()?;
        self.progress.publication = Publication::Requested;
        self.publish("Publishing");
        let result = stage.publish(parent, name);
        if let Err(error) = result {
            self.progress.publication = match &error {
                Error::Refused(_) => Publication::NotRequested,
                Error::Io(e) if e.raw_os_error() == Some(libc::EEXIST) => Publication::NotRequested,
                _ => Publication::Uncertain,
            };
            self.publish("Publication refused; verify destination if outcome is uncertain");
            return Err(error);
        }
        self.progress.publication = Publication::Confirmed;
        self.progress.files_done += 1;
        record_item(
            &self.hooks.items,
            ItemResult {
                path: name.into(),
                result: "Downloaded".into(),
            },
        );
        self.publish("Finalizing download");
        self.checkpoint(Boundary::Published, &node.remote_path, Some(&temporary))?;
        self.verify()?;
        Ok(())
    }
}
fn node_size(node: &Node) -> u64 {
    if node.kind == Kind::File {
        node.attrs.size.unwrap_or(0)
    } else {
        node.children.iter().map(node_size).sum()
    }
}

pub async fn run(
    connection: &Connection,
    job: &Job,
    hooks: &Hooks,
    cancel: &CancellationToken,
) -> Result<Outcome> {
    check_cancel(cancel)?;
    let mut count = 0;
    let mut total = 0;
    hooks.progress.lock().unwrap().phase = "Scanning folder tree".into();
    let node = match job.direction {
        Direction::Upload => {
            let name = job
                .local
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| Error::Refused("Choose a named file or folder".into()))?
                .to_string();
            let (parent, _) = fs::local_root(
                job.local
                    .parent()
                    .ok_or_else(|| Error::Refused("Source has no parent".into()))?,
            )?;
            local_plan(
                Arc::new(parent),
                name,
                0,
                &mut count,
                &mut total,
                cancel,
                hooks,
            )?
        }
        Direction::Download => {
            // Ancestor validation must describe the exact path later sent to
            // OPEN. Lexically removing a symlink/.. component would otherwise
            // check one directory while the server opens another. Browser
            // listings already return normalized absolute paths; reject other
            // source spellings rather than silently select different bytes.
            if fs::normalize_remote(&job.remote)? != job.remote {
                return Err(Error::Refused(
                    "Download source must be a normalized absolute remote path; refresh the remote folder and select the item again".into(),
                ));
            }
            fs::remote_dir(&connection.sftp, crate::remote_parent(&job.remote)).await?;
            remote_plan(
                connection,
                job.remote.clone(),
                0,
                &mut count,
                &mut total,
                cancel,
            )
            .await?
        }
    };
    let mut engine = Engine {
        connection,
        hooks,
        cancel,
        rate: PayloadRate::new(Instant::now()),
        progress: Progress {
            total,
            files_total: files_count(&node),
            ..Progress::default()
        },
    };
    engine.publish("Transferring");
    match job.direction {
        Direction::Upload => {
            let parent = fs::remote_dir(&connection.sftp, &job.remote).await?;
            engine.upload_node(&node, parent).await?;
        }
        Direction::Download => {
            let (parent, display) = fs::local_root(&job.local)?;
            engine
                .download_node(&node, Arc::new(parent), display)
                .await?;
        }
    }
    engine.publish("Complete");
    Ok(Outcome {
        progress: engine.progress,
    })
}

fn same_local(a: &cap_std::fs::Metadata, b: &cap_std::fs::Metadata) -> bool {
    use cap_std::fs::MetadataExt;
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.modified().ok() == b.modified().ok()
        && a.mode() == b.mode()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn payload_speed_uses_recent_bytes_and_excludes_verification_and_waits() {
        let start = Instant::now();
        let mut rate = PayloadRate::new(start);
        assert_eq!(
            rate.update(200, true, start + Duration::from_millis(200)),
            1000.0
        );
        assert_eq!(
            rate.update(600, true, start + Duration::from_millis(400)),
            2000.0
        );
        // Verification/waits reset the sample without altering the caller's
        // exact cumulative byte count or diluting the following copy's rate.
        assert_eq!(
            rate.update(600, false, start + Duration::from_secs(20)),
            0.0
        );
        assert_eq!(
            rate.update(800, true, start + Duration::from_millis(20200)),
            1000.0
        );
    }

    #[test]
    fn frequent_payload_updates_preserve_the_previous_measurement() {
        let start = Instant::now();
        let mut rate = PayloadRate::new(start);
        assert_eq!(
            rate.update(100, true, start + Duration::from_millis(100)),
            0.0
        );
        assert_eq!(
            rate.update(200, true, start + Duration::from_millis(200)),
            1000.0
        );
        assert_eq!(
            rate.update(800, true, start + Duration::from_millis(250)),
            1000.0
        );
        assert_eq!(
            rate.update(1000, true, start + Duration::from_millis(400)),
            4000.0
        );
    }

    #[test]
    fn large_tree_diagnostics_are_bounded_and_keep_latest_failure() {
        let items = Mutex::new(Vec::new());
        for index in 0..50_000 {
            record_item(
                &items,
                ItemResult {
                    path: format!("/tree/item-{index}"),
                    result: "Uploaded; private staging retained".into(),
                },
            );
        }
        record_item(
            &items,
            ItemResult {
                path: "/tree/failed-item".into(),
                result: "Disk full; transfer failed".into(),
            },
        );
        let items = items.lock().unwrap();
        assert!(
            items.len() <= MAX_ITEM_RESULTS,
            "{} retained diagnostics",
            items.len()
        );
        assert_eq!(items.first().unwrap().path, "/tree/item-0");
        assert!(items[MAX_ITEM_RESULTS - 2].result.contains("omitted"));
        assert_eq!(items.last().unwrap().result, "Disk full; transfer failed");
    }

    #[test]
    fn oversized_unicode_diagnostics_do_not_retain_packet_allocations() {
        let items = Mutex::new(Vec::new());
        record_item(
            &items,
            ItemResult {
                path: "é".repeat(128 * 1024),
                result: "錯".repeat(128 * 1024),
            },
        );
        let items = items.lock().unwrap();
        for text in [&items[0].path, &items[0].result] {
            assert!(text.len() <= MAX_DIAGNOSTIC_BYTES);
            assert!(text.capacity() <= MAX_DIAGNOSTIC_BYTES);
            assert!(text.ends_with("[diagnostic truncated]"));
        }
    }
}
