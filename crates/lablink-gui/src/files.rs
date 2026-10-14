//! Native Files workspace. Only bounded messages and snapshots cross into UI.
use eframe::egui::{self, RichText};
use lablink_files::{
    preferences::Preferences,
    transfer::ItemResult,
    worker::{BrowseCmd, Event, Handle, Worker},
    ConflictAction, Direction, Entry, Job, Kind, Listing, Side,
};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        mpsc::{self, Receiver, SyncSender},
        Arc,
    },
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sort {
    Name,
    Type,
    Size,
    Modified,
}
struct Browser {
    path: String,
    edit_path: String,
    entries: Vec<Entry>,
    selected: BTreeSet<String>,
    anchor: Option<usize>,
    history: Vec<String>,
    generation: u64,
    loading: bool,
    ready: bool,
    error: Option<String>,
    sort: Sort,
    descending: bool,
    show_location: bool,
}
impl Default for Browser {
    fn default() -> Self {
        Self {
            path: String::new(),
            edit_path: String::new(),
            entries: Vec::new(),
            selected: BTreeSet::new(),
            anchor: None,
            history: Vec::new(),
            generation: 0,
            loading: false,
            ready: false,
            error: None,
            sort: Sort::Name,
            descending: false,
            show_location: false,
        }
    }
}
impl Browser {
    fn sorted(&self) -> Vec<&Entry> {
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .filter(|entry| !lablink_files::fs::is_staging_name(&entry.name))
            .collect();
        entries.sort_by(|a, b| {
            let folders = (a.kind != Kind::Directory).cmp(&(b.kind != Kind::Directory));
            let order = match self.sort {
                Sort::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                Sort::Type => a.kind.cmp(&b.kind),
                Sort::Size => a.size.cmp(&b.size),
                Sort::Modified => a.modified.cmp(&b.modified),
            }
            .then_with(|| a.name.cmp(&b.name));
            folders.then(if self.descending {
                order.reverse()
            } else {
                order
            })
        });
        entries
    }
}
#[derive(Clone)]
struct Drag {
    side: Side,
    device: String,
    path: String,
    names: Vec<String>,
}
struct TransferRow {
    job: Job,
    handle: Handle,
    result: Option<std::result::Result<(), String>>,
}
struct Conflict {
    id: u64,
    path: String,
    kind: Kind,
    reply: lablink_files::worker::ConflictReply,
}
struct EditDialog {
    focus: bool,
    side: Side,
    old: Option<String>,
    name: String,
}
enum DialogRequest {
    BrowseLocal,
    UploadFiles,
    UploadFolder,
    Download(Vec<String>),
}
struct DesktopDrop {
    device: String,
    remote: String,
    paths: Vec<PathBuf>,
}
struct DialogResult {
    device: String,
    remote: String,
    request: DialogRequest,
    paths: Vec<PathBuf>,
}
#[derive(Clone, Copy)]
struct Availability {
    daemon: bool,
    transfers: bool,
    pane_height: f32,
}
enum Action {
    Navigate(Side, String, bool),
    Back(Side),
    Favorite(Side),
    Edit(Side, Option<String>),
    Transfer(Side),
    Dialog(DialogRequest),
}

pub struct Files {
    worker: Worker,
    events: Receiver<Event>,
    device: Option<String>,
    local: Browser,
    remote: Browser,
    preferences: Preferences,
    preferences_loaded: bool,
    preferences_dirty: bool,
    queue: Vec<TransferRow>,
    next_id: u64,
    conflicts: Vec<Conflict>,
    edit: Option<EditDialog>,
    notice: Option<String>,
    dialog_tx: SyncSender<DialogResult>,
    dialogs: Receiver<DialogResult>,
    dialog_busy: bool,
    daemon_available: bool,
    desktop_drop: Option<DesktopDrop>,
    details_request: Option<String>,
}
impl Files {
    pub fn new(socket: PathBuf, ctx: egui::Context) -> Self {
        let repaint = {
            let ctx = ctx.clone();
            Arc::new(move || ctx.request_repaint()) as Arc<dyn Fn() + Send + Sync>
        };
        let (worker, events) = Worker::spawn(socket, repaint);
        let (dialog_tx, dialogs) = mpsc::sync_channel(2);
        let _ = worker.browse(BrowseCmd::LoadPreferences);
        Self {
            worker,
            events,
            device: None,
            local: Browser::default(),
            remote: Browser::default(),
            preferences: Preferences::default(),
            preferences_loaded: false,
            preferences_dirty: false,
            queue: Vec::new(),
            next_id: 1,
            conflicts: Vec::new(),
            edit: None,
            notice: None,
            dialog_tx,
            dialogs,
            dialog_busy: false,
            daemon_available: false,
            desktop_drop: None,
            details_request: None,
        }
    }
    pub fn selected_device(&self) -> Option<&str> {
        self.device.as_deref()
    }
    pub fn take_details_request(&mut self) -> Option<String> {
        self.details_request.take()
    }
    pub fn appearance(&self) -> &str {
        if self.preferences.appearance.is_empty() {
            "True Black"
        } else {
            &self.preferences.appearance
        }
    }
    pub fn set_appearance(&mut self, appearance: String) {
        self.preferences.appearance = appearance;
        self.preferences_dirty = true;
    }
    pub fn open(&mut self, device: String) {
        if self.device.as_ref() == Some(&device) && self.local.ready && self.remote.ready {
            return;
        }
        self.device = Some(device.clone());
        self.local = Browser {
            generation: self.local.generation + 1,
            ..Browser::default()
        };
        self.remote = Browser {
            generation: self.remote.generation + 1,
            ..Browser::default()
        };
        self.edit = None;
        let locations = self
            .preferences
            .devices
            .get(&device)
            .cloned()
            .unwrap_or_default();
        self.navigate(
            Side::Local,
            locations.local.unwrap_or_else(local_home),
            false,
        );
        self.navigate(
            Side::Remote,
            locations.remote.unwrap_or_else(|| ".".into()),
            false,
        );
    }
    fn browser(&self, side: Side) -> &Browser {
        if side == Side::Local {
            &self.local
        } else {
            &self.remote
        }
    }
    fn browser_mut(&mut self, side: Side) -> &mut Browser {
        if side == Side::Local {
            &mut self.local
        } else {
            &mut self.remote
        }
    }
    fn navigate(&mut self, side: Side, path: String, history: bool) {
        let Some(device) = self.device.clone() else {
            return;
        };
        // An edit must never follow navigation into another directory.
        if self.edit.as_ref().is_some_and(|edit| edit.side == side) {
            self.edit = None;
            self.notice = Some("Folder navigation cancelled the pending edit. Open it again in the destination folder.".into());
        }
        let browser = self.browser_mut(side);
        if history && browser.ready && browser.path != path {
            browser.history.push(browser.path.clone());
        }
        browser.generation += 1;
        browser.loading = true;
        browser.ready = false;
        browser.error = None;
        let generation = browser.generation;
        if let Err(e) = self.worker.browse(BrowseCmd::List {
            generation,
            device,
            side,
            path,
        }) {
            let browser = self.browser_mut(side);
            browser.loading = false;
            browser.error = Some(e.to_string());
        }
    }
    pub fn drain(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                Event::Listed {
                    generation,
                    device,
                    side,
                    result,
                } => {
                    if self.device.as_ref() != Some(&device)
                        || self.browser(side).generation != generation
                    {
                        continue;
                    }
                    let browser = self.browser_mut(side);
                    browser.loading = false;
                    match result {
                        Ok(Listing { path, entries }) => {
                            browser.edit_path = path.clone();
                            browser.path = path.clone();
                            browser.entries = entries;
                            browser.selected.clear();
                            browser.anchor = None;
                            browser.ready = true;
                            browser.error = None;
                            let locations = self.preferences.devices.entry(device).or_default();
                            if side == Side::Local {
                                locations.local = Some(path);
                            } else {
                                locations.remote = Some(path);
                            }
                            self.preferences_dirty = true;
                        }
                        Err(error) => {
                            browser.error = Some(error);
                            browser.ready = false;
                        }
                    }
                }
                Event::Preferences(result) => {
                    self.preferences_loaded = true;
                    match result {
                        Ok(preferences) => {
                            self.preferences = preferences;
                            if let Some(device) = self.device.clone() {
                                self.open(device);
                            }
                        }
                        Err(e) => self.notice = Some(e),
                    }
                }
                Event::PreferencesSaved(result) => {
                    if let Err(e) = result {
                        self.notice = Some(e);
                    }
                }
                Event::Conflict {
                    id,
                    path,
                    kind,
                    reply,
                } => self.conflicts.push(Conflict {
                    id,
                    path,
                    kind,
                    reply,
                }),
                Event::Finished { id, result } => {
                    if let Some(row) = self.queue.iter_mut().find(|row| row.job.id == id) {
                        row.result = Some(result.map(|_| ()));
                    }
                    self.conflicts.retain(|c| c.id != id);
                    // Only the displayed device is refreshed; transfers keep their captured device.
                    if self.queue.iter().any(|row| {
                        row.job.id == id && self.device.as_ref() == Some(&row.job.device)
                    }) {
                        self.navigate(Side::Local, self.local.path.clone(), false);
                        self.navigate(Side::Remote, self.remote.path.clone(), false);
                    }
                }
            }
        }
        while let Ok(dialog) = self.dialogs.try_recv() {
            self.dialog_busy = false;
            match dialog.request {
                DialogRequest::BrowseLocal => {
                    if self.device.as_ref() == Some(&dialog.device) {
                        if let Some(path) = dialog.paths.first() {
                            if let Some(path) = path.to_str() {
                                self.navigate(Side::Local, path.to_owned(), true);
                            } else {
                                self.notice = Some("Non-UTF-8 paths are unsupported".into());
                            }
                        }
                    }
                }
                DialogRequest::UploadFiles | DialogRequest::UploadFolder => {
                    for path in dialog.paths {
                        self.enqueue(
                            dialog.device.clone(),
                            Direction::Upload,
                            path,
                            dialog.remote.clone(),
                        );
                    }
                }
                DialogRequest::Download(paths) => {
                    if let Some(local) = dialog.paths.first() {
                        for path in paths {
                            self.enqueue(
                                dialog.device.clone(),
                                Direction::Download,
                                local.clone(),
                                path,
                            );
                        }
                    }
                }
            }
        }
        if self.preferences_dirty && self.preferences_loaded {
            match self
                .worker
                .browse(BrowseCmd::SavePreferences(self.preferences.clone()))
            {
                Ok(()) => self.preferences_dirty = false,
                Err(e) => self.notice = Some(e.to_string()),
            }
        }
    }
    fn enqueue(&mut self, device: String, direction: Direction, local: PathBuf, remote: String) {
        if self.queue.len() >= 512 {
            self.notice =
                Some("Clear completed transfers before adding more (512-row limit)".into());
            return;
        }
        let job = Job {
            id: self.next_id,
            device,
            direction,
            local,
            remote,
        };
        match self.worker.enqueue(job.clone()) {
            Ok(handle) => {
                self.next_id += 1;
                self.queue.push(TransferRow {
                    job,
                    handle,
                    result: None,
                });
            }
            Err(e) => self.notice = Some(e.to_string()),
        }
    }
    fn transfers_ready(&self) -> bool {
        self.daemon_available && self.local.ready && self.remote.ready
    }
    fn transfer_selected(&mut self, side: Side) {
        if !self.transfers_ready() {
            return;
        }
        let Some(device) = self.device.clone() else {
            return;
        };
        let names: Vec<_> = self.browser(side).selected.iter().cloned().collect();
        for name in names {
            if side == Side::Local {
                self.enqueue(
                    device.clone(),
                    Direction::Upload,
                    PathBuf::from(&self.local.path).join(name),
                    self.remote.path.clone(),
                );
            } else if let Ok(remote) = lablink_files::remote_join(&self.remote.path, &name) {
                self.enqueue(
                    device.clone(),
                    Direction::Download,
                    PathBuf::from(&self.local.path),
                    remote,
                );
            }
        }
    }
    fn start_dialog(&mut self, request: DialogRequest, ctx: &egui::Context) {
        if self.dialog_busy {
            return;
        }
        let Some(device) = self.device.clone() else {
            return;
        };
        self.dialog_busy = true;
        let (local, remote, tx, ctx) = (
            self.local.path.clone(),
            self.remote.path.clone(),
            self.dialog_tx.clone(),
            ctx.clone(),
        );
        std::thread::spawn(move || {
            let dialog = rfd::FileDialog::new().set_directory(&local);
            let paths = match &request {
                DialogRequest::UploadFiles => dialog
                    .set_title("Choose files to upload")
                    .pick_files()
                    .unwrap_or_default(),
                DialogRequest::UploadFolder => dialog
                    .set_title("Choose folder to upload recursively")
                    .pick_folder()
                    .into_iter()
                    .collect(),
                DialogRequest::BrowseLocal => dialog
                    .set_title("Open local folder")
                    .pick_folder()
                    .into_iter()
                    .collect(),
                DialogRequest::Download(_) => dialog
                    .set_title("Choose download destination")
                    .pick_folder()
                    .into_iter()
                    .collect(),
            };
            let _ = tx.send(DialogResult {
                device,
                remote,
                request,
                paths,
            });
            ctx.request_repaint();
        });
    }
    pub fn ui(&mut self, ui: &mut egui::Ui, devices: &[String], daemon_available: bool) {
        self.daemon_available = daemon_available;
        if !daemon_available {
            ui.colored_label(
                crate::theme::warning(ui),
                "Remote actions require a matching Files daemon and a trusted device at this site.",
            );
        }
        let ctx = ui.ctx().clone();
        ui.horizontal_wrapped(|ui| {
            ui.heading("Files");
            ui.weak("Connected device");
            let mut device = self.device.clone().unwrap_or_default();
            egui::ComboBox::from_id_salt("files-device")
                .selected_text(if device.is_empty() {
                    "Select device"
                } else {
                    &device
                })
                .show_ui(ui, |ui| {
                    for name in devices {
                        ui.selectable_value(&mut device, name.clone(), name);
                    }
                });
            if !device.is_empty() && self.device.as_ref() != Some(&device) {
                self.open(device);
            }
            if ui
                .add_enabled(self.device.is_some(), egui::Button::new("Device Details"))
                .clicked()
            {
                self.details_request = self.device.clone();
            }
            if self.dialog_busy {
                ui.spinner();
                ui.label("Native selection dialog open");
            }
        });
        ui.weak("Ctrl or Shift to select multiple items. Folders include their contents recursively. Drag across panes to transfer.");
        if let Some(notice) = self.notice.clone() {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(crate::theme::error(ui), notice);
                if ui.button("Dismiss").clicked() {
                    self.notice = None;
                }
            });
        }
        if self.device.is_none() {
            ui.label("Select a LabLink device to open local and remote files.");
            return;
        }
        let device = self.device.clone().unwrap();
        let locations = self
            .preferences
            .devices
            .get(&device)
            .cloned()
            .unwrap_or_default();
        let mut actions = Vec::new();
        let pane_height = (ui.available_height()
            - if self.queue.is_empty() { 150.0 } else { 235.0 })
        .clamp(250.0, 580.0);
        let availability = Availability {
            daemon: daemon_available,
            transfers: self.transfers_ready(),
            pane_height,
        };
        let internal_drop_allowed = self.edit.is_none()
            && self.conflicts.is_empty()
            && self.desktop_drop.is_none()
            && !self.dialog_busy;
        ui.columns(2, |columns| {
            for (index, side) in [(0, Side::Local), (1, Side::Remote)] {
                let favorites = if side == Side::Local {
                    &locations.local_favorites
                } else {
                    &locations.remote_favorites
                };
                let browser = self.browser_mut(side);
                let response = egui::Frame::group(columns[index].style())
                    .fill(columns[index].visuals().extreme_bg_color)
                    .show(&mut columns[index], |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.set_min_height(pane_height);
                        egui::ScrollArea::vertical()
                            .id_salt(("pane", side == Side::Remote))
                            .max_height(pane_height)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                browser_ui(
                                    ui,
                                    browser,
                                    side,
                                    &device,
                                    favorites,
                                    availability,
                                    &mut actions,
                                )
                            });
                    })
                    .response;
                let internal = egui::DragAndDrop::payload::<Drag>(&ctx)
                    .is_some_and(|drag| drag.side != side && drag.device == device);
                let external =
                    side == Side::Remote && ctx.input(|i| !i.raw.hovered_files.is_empty());
                let hovered = ctx.input(|i| {
                    i.pointer
                        .hover_pos()
                        .is_some_and(|p| response.rect.contains(p))
                });
                if internal && hovered || external {
                    let valid = self.transfers_ready();
                    let color = if valid {
                        crate::theme::ACCENT
                    } else {
                        crate::theme::WARNING
                    };
                    columns[index].painter().rect_stroke(
                        response.rect,
                        8,
                        egui::Stroke::new(2.0, color),
                        egui::StrokeKind::Inside,
                    );
                    let label = if !valid {
                        "Destination unavailable"
                    } else if external {
                        "Desktop drop: confirm upload destination"
                    } else if side == Side::Remote {
                        "Release to upload into this folder"
                    } else {
                        "Release to download into this folder"
                    };
                    columns[index].painter().text(
                        response.rect.center_bottom() - egui::vec2(0.0, 16.0),
                        egui::Align2::CENTER_BOTTOM,
                        label,
                        egui::FontId::proportional(14.0),
                        color,
                    );
                }
                if internal_drop_allowed
                    && daemon_available
                    && self.local.ready
                    && self.remote.ready
                {
                    let released_here = ctx.input(|i| {
                        i.events
                            .iter()
                            .rev()
                            .find_map(|event| {
                                if let egui::Event::PointerButton {
                                    pos,
                                    button: egui::PointerButton::Primary,
                                    pressed: false,
                                    ..
                                } = event
                                {
                                    Some(
                                        response
                                            .rect
                                            .intersect(columns[index].clip_rect())
                                            .contains(*pos),
                                    )
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(false)
                    });
                    // Use the release event position. A later mouse move in the
                    // same frame must not redirect or discard a deliberate drop.
                    if let Some(drag) = released_here
                        .then(|| egui::DragAndDrop::take_payload::<Drag>(&ctx))
                        .flatten()
                    {
                        if drag.side != side && drag.device == device {
                            for name in &drag.names {
                                if side == Side::Remote {
                                    self.enqueue(
                                        device.clone(),
                                        Direction::Upload,
                                        PathBuf::from(&drag.path).join(name),
                                        self.remote.path.clone(),
                                    );
                                } else if let Ok(path) =
                                    lablink_files::remote_join(&drag.path, name)
                                {
                                    self.enqueue(
                                        device.clone(),
                                        Direction::Download,
                                        PathBuf::from(&self.local.path),
                                        path,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        });
        // Winit X11 does not expose XDND coordinates. Never route desktop
        // drops using a stale mouse position; capture and confirm the destination.
        let dropped = ctx.input(|i| i.raw.dropped_files.clone());
        if !dropped.is_empty() {
            if self.transfers_ready() && self.desktop_drop.is_none() && dropped.len() <= 128 {
                self.desktop_drop = Some(DesktopDrop {
                    device: device.clone(),
                    remote: self.remote.path.clone(),
                    paths: dropped
                        .iter()
                        .map(|file| file.path().to_path_buf())
                        .collect(),
                });
            } else {
                self.notice = Some("Desktop drop unavailable. Select a connected device and ready destination; drop at most 128 items at a time.".into());
            }
        }
        for action in actions {
            match action {
                Action::Navigate(side, path, history) => self.navigate(side, path, history),
                Action::Back(side) => {
                    if let Some(path) = self.browser_mut(side).history.pop() {
                        self.navigate(side, path, false);
                    }
                }
                Action::Favorite(side) => {
                    let path = self.browser(side).path.clone();
                    let locations = self.preferences.devices.entry(device.clone()).or_default();
                    let favorites = if side == Side::Local {
                        &mut locations.local_favorites
                    } else {
                        &mut locations.remote_favorites
                    };
                    if favorites.contains(&path) {
                        favorites.retain(|p| p != &path);
                    } else if favorites.len() < 64 {
                        favorites.push(path);
                    }
                    self.preferences_dirty = true;
                }
                Action::Edit(side, old) => {
                    self.edit = Some(EditDialog {
                        focus: true,
                        side,
                        name: old.clone().unwrap_or_default(),
                        old,
                    })
                }
                Action::Transfer(side) => self.transfer_selected(side),
                Action::Dialog(request) => self.start_dialog(request, &ctx),
            }
        }
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            let ready = daemon_available && self.remote.ready;
            if ui
                .add_enabled(
                    ready && !self.dialog_busy,
                    egui::Button::new("Upload files…"),
                )
                .clicked()
            {
                self.start_dialog(DialogRequest::UploadFiles, &ctx);
            }
            if ui
                .add_enabled(
                    ready && !self.dialog_busy,
                    egui::Button::new("Upload folder…"),
                )
                .clicked()
            {
                self.start_dialog(DialogRequest::UploadFolder, &ctx);
            }
            if ui
                .add_enabled(
                    ready && !self.dialog_busy && !self.remote.selected.is_empty(),
                    egui::Button::new("Download to folder…"),
                )
                .clicked()
            {
                let paths = self
                    .remote
                    .selected
                    .iter()
                    .filter_map(|n| lablink_files::remote_join(&self.remote.path, n).ok())
                    .collect();
                self.start_dialog(DialogRequest::Download(paths), &ctx);
            }
        });
        self.queue_ui(ui);
        self.edit_ui(&ctx);
        self.conflict_ui(&ctx);
        if self.conflicts.is_empty() {
            self.desktop_drop_ui(&ctx);
        }
        if self.queue.iter().any(|row| row.result.is_none()) {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }
    fn desktop_drop_ui(&mut self, ctx: &egui::Context) {
        let Some(drop) = &self.desktop_drop else {
            return;
        };
        let mut confirm = false;
        let mut cancel = false;
        egui::Modal::new(egui::Id::new("desktop-drop")).show(ctx, |ui| {
            ui.heading("Upload desktop files?");
            ui.label(format!("{} item(s) from this computer", drop.paths.len()));
            ui.strong(format!("Remote device: {}", drop.device));
            ui.monospace(&drop.remote);
            ui.weak("Folders include their contents recursively. Existing files require a conflict decision.");
            for path in drop.paths.iter().take(5) {
                ui.label(path.file_name().unwrap_or_default().to_string_lossy());
            }
            ui.horizontal(|ui| {
                confirm = ui.button("Upload to this folder").clicked();
                cancel = ui.button("Cancel").clicked();
            });
        });
        if confirm {
            if let Some(drop) = self.desktop_drop.take() {
                for path in drop.paths {
                    self.enqueue(
                        drop.device.clone(),
                        Direction::Upload,
                        path,
                        drop.remote.clone(),
                    );
                }
            }
        } else if cancel {
            self.desktop_drop = None;
        }
    }
    fn queue_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong(format!("Transfers ({})", self.queue.len()));
            if ui.button("Cancel all").clicked() {
                for row in &self.queue {
                    if row.result.is_none() {
                        row.handle.cancel.cancel();
                    }
                }
            }
            if ui.button("Clear completed").clicked() {
                self.queue.retain(|row| row.result.is_none());
            }
        });
        if self.queue.is_empty() {
            ui.weak("Upload or download to add work to the background queue.");
            return;
        }
        let mut retries = Vec::new();
        egui::ScrollArea::vertical()
            .id_salt("files-queue")
            .max_height(ui.available_height().max(50.0))
            .show(ui, |ui| {
                for row in self.queue.iter().rev() {
                    let progress = row.handle.progress.lock().unwrap().clone();
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!(
                            "#{} · {} · {}",
                            row.job.id,
                            row.job.device,
                            if row.job.direction == Direction::Upload {
                                "Upload"
                            } else {
                                "Download"
                            }
                        ));
                        ui.label(if row.job.direction == Direction::Upload {
                            row.job.local.display().to_string()
                        } else {
                            row.job.remote.clone()
                        });
                        match &row.result {
                            None => {
                                ui.label(if row.handle.cancel.is_cancelled() {
                                    "Cancelling…"
                                } else {
                                    &progress.phase
                                });
                                if ui.button("Cancel").clicked() {
                                    row.handle.cancel.cancel();
                                }
                            }
                            Some(Ok(())) => {
                                ui.colored_label(
                                    crate::theme::success(ui),
                                    format!(
                                        "Complete · {} files · {} skipped",
                                        progress.files_done, progress.skipped
                                    ),
                                );
                            }
                            Some(Err(error)) => {
                                ui.colored_label(
                                    if error.starts_with("Transfer cancelled") {
                                        ui.visuals().weak_text_color()
                                    } else {
                                        ui.visuals().error_fg_color
                                    },
                                    error,
                                );
                                if ui.button("Retry").clicked() {
                                    retries.push(row.job.clone());
                                }
                            }
                        }
                    });
                    if let Some(current) = &progress.current {
                        ui.weak(format!("Current file: {current}"));
                    }
                    let fraction = if progress.total > 0 {
                        (progress.bytes as f64 / progress.total as f64).clamp(0.0, 1.0) as f32
                    } else if matches!(row.result, Some(Ok(()))) {
                        1.0
                    } else {
                        0.0
                    };
                    ui.add(egui::ProgressBar::new(fraction).text(format!(
                        "{:.0}% · {} / {} bytes · {} / {} files · {:.1} MiB/s",
                        fraction * 100.0,
                        progress.bytes,
                        progress.total,
                        progress.files_done,
                        progress.files_total,
                        progress.bytes_per_second / (1024.0 * 1024.0)
                    )));
                    if row.result.is_none()
                        && progress.bytes_per_second > 0.0
                        && progress.bytes < progress.total
                    {
                        let seconds =
                            (progress.total - progress.bytes) as f64 / progress.bytes_per_second;
                        ui.weak(format!(
                            "Copy estimate: {:.0}s remaining, verification follows",
                            seconds
                        ));
                    }
                    egui::CollapsingHeader::new("Individual results")
                        .id_salt(row.job.id)
                        .show(ui, |ui| {
                            let items = row.handle.items.lock().unwrap();
                            egui::ScrollArea::vertical()
                                .id_salt(("item-results", row.job.id))
                                .max_height(150.0)
                                .show_rows(ui, 22.0, items.len(), |ui, range| {
                                    for ItemResult { path, result } in &items[range] {
                                        ui.label(format!("{result}: {path}"));
                                    }
                                });
                        });
                    ui.separator();
                }
            });
        for job in retries {
            self.enqueue(job.device, job.direction, job.local, job.remote);
        }
    }
    fn edit_ui(&mut self, ctx: &egui::Context) {
        let Some(mut edit) = self.edit.take() else {
            return;
        };
        let mut close = false;
        let mut submit = false;
        egui::Window::new(if edit.old.is_some() {
            "Rename item"
        } else {
            "Create folder"
        })
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .default_width(360.0)
        .show(ctx, |ui| {
            ui.label(if edit.side == Side::Local {
                "Local computer"
            } else {
                "Remote device"
            });
            ui.label("Name (one path component)");
            let input = ui.text_edit_singleline(&mut edit.name);
            if edit.focus && ui.is_visible() && !ui.is_sizing_pass() {
                if input.has_focus() {
                    edit.focus = false;
                } else {
                    input.request_focus();
                    ui.ctx().request_repaint();
                }
            }
            let valid = lablink_files::validate_name(&edit.name).is_ok();
            if !valid {
                ui.label("Use a name without slashes, control characters, or dot segments.");
            }
            ui.horizontal(|ui| {
                submit = ui.add_enabled(valid, egui::Button::new("Save")).clicked()
                    || (valid
                        && input.lost_focus()
                        && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                close = ui.button("Cancel").clicked();
            });
        });
        if submit {
            let device = self.device.clone().unwrap();
            let browser = self.browser_mut(edit.side);
            browser.generation += 1;
            browser.loading = true;
            browser.ready = false;
            let cmd = if let Some(old) = edit.old {
                BrowseCmd::Rename {
                    generation: browser.generation,
                    device,
                    side: edit.side,
                    path: browser.path.clone(),
                    old,
                    new: edit.name,
                }
            } else {
                BrowseCmd::Mkdir {
                    generation: browser.generation,
                    device,
                    side: edit.side,
                    path: browser.path.clone(),
                    name: edit.name,
                }
            };
            if let Err(e) = self.worker.browse(cmd) {
                let browser = self.browser_mut(edit.side);
                browser.loading = false;
                browser.error = Some(e.to_string());
            }
        } else if !close {
            self.edit = Some(edit);
        }
    }
    fn conflict_ui(&mut self, ctx: &egui::Context) {
        let Some(conflict) = self.conflicts.first() else {
            return;
        };
        let mut choice = None;
        egui::Modal::new(egui::Id::new("files-conflict")).show(ctx, |ui| {
            ui.heading("Destination already exists");
            if let Some(row) = self.queue.iter().find(|row| row.job.id == conflict.id) {
                ui.label(format!(
                    "Transfer #{} · {} · {}",
                    conflict.id,
                    row.job.device,
                    if row.job.direction == Direction::Upload {
                        "Upload to remote"
                    } else {
                        "Download to local"
                    }
                ));
            } else {
                ui.label(format!("Transfer #{}", conflict.id));
            }
            ui.monospace(&conflict.path);
            if conflict.kind == Kind::Directory {
                ui.label("Merge keeps both folders. Each existing file requires its own decision.");
            } else {
                ui.label("File Replace is refused because atomic comparison is unavailable. Choose Skip or Keep Both.");
            }
            ui.horizontal(|ui| {
                for (label, action) in [
                    ("Skip", ConflictAction::Skip),
                    (
                        if conflict.kind == Kind::Directory {
                            "Merge folders"
                        } else {
                            "Replace"
                        },
                        ConflictAction::Replace,
                    ),
                    ("Keep Both", ConflictAction::KeepBoth),
                ] {
                    if ui.add_enabled(action!=ConflictAction::Replace || conflict.kind==Kind::Directory,egui::Button::new(label))
                        .on_disabled_hover_text("File replacement requires atomic compare-and-swap and is refused by this backend").clicked() {
                        choice = Some(action);
                    }
                }
            });
            if ui.button("Cancel transfer").clicked() {
                if let Some(row) = self.queue.iter().find(|r| r.job.id == conflict.id) {
                    row.handle.cancel.cancel();
                }
            }
        });
        if let Some(choice) = choice {
            let conflict = self.conflicts.remove(0);
            let _ = conflict.reply.send(choice);
        }
    }
}

fn browser_ui(
    ui: &mut egui::Ui,
    browser: &mut Browser,
    side: Side,
    device: &str,
    favorites: &[String],
    availability: Availability,
    actions: &mut Vec<Action>,
) {
    let compact_toolbar = ui.available_width() < 450.0;
    ui.strong(if side == Side::Local {
        "Local computer".to_string()
    } else {
        format!("Remote · {device}")
    });
    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(!browser.history.is_empty(), egui::Button::new("Back"))
            .clicked()
        {
            actions.push(Action::Back(side));
        }
        if ui.button("Up").clicked() {
            let path = PathBuf::from(&browser.path)
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| "/".into());
            actions.push(Action::Navigate(side, path, true));
        }
        if ui.button("Home").clicked() {
            actions.push(Action::Navigate(
                side,
                if side == Side::Local {
                    local_home()
                } else {
                    ".".into()
                },
                true,
            ));
        }
        if ui.button("Refresh").clicked() {
            actions.push(Action::Navigate(side, browser.path.clone(), false));
        }
        if side == Side::Local && !compact_toolbar && ui.button("Browse…").clicked() {
            actions.push(Action::Dialog(DialogRequest::BrowseLocal));
        }
    });
    if !compact_toolbar || browser.show_location {
        egui::CollapsingHeader::new("Location")
            .id_salt(("location", side == Side::Remote))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let response = ui.add(
                        egui::TextEdit::singleline(&mut browser.edit_path)
                            .desired_width((ui.available_width() - 45.0).max(70.0))
                            .hint_text("Absolute directory path"),
                    );
                    if ui.button("Go").clicked()
                        || response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
                    {
                        actions.push(Action::Navigate(side, browser.edit_path.clone(), true));
                    }
                });
            });
    }
    egui::ScrollArea::horizontal()
        .id_salt(("breadcrumbs", side == Side::Remote))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui.small_button("/").clicked() {
                    actions.push(Action::Navigate(side, "/".into(), true));
                }
                let mut prefix = String::new();
                for name in browser.path.split('/').filter(|s| !s.is_empty()) {
                    prefix.push('/');
                    prefix.push_str(name);
                    ui.weak("/");
                    if ui.small_button(name).clicked() {
                        actions.push(Action::Navigate(side, prefix.clone(), true));
                    }
                }
            })
        });
    if !compact_toolbar {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    browser.ready,
                    egui::Button::new(if favorites.contains(&browser.path) {
                        "Remove favorite"
                    } else {
                        "Favorite"
                    }),
                )
                .clicked()
            {
                actions.push(Action::Favorite(side));
            }
            egui::ComboBox::from_id_salt(("favorites", side == Side::Remote))
                .selected_text("Favorite folders")
                .show_ui(ui, |ui| {
                    for path in favorites {
                        if ui.selectable_label(false, path).clicked() {
                            actions.push(Action::Navigate(side, path.clone(), true));
                        }
                    }
                });
        });
    }
    ui.horizontal_wrapped(|ui| {
        let usable = browser.ready && (side == Side::Local || availability.daemon);
        let operations = |ui: &mut egui::Ui, actions: &mut Vec<Action>| {
            if ui.add_enabled(usable, egui::Button::new("New folder")).clicked() {
                actions.push(Action::Edit(side, None)); ui.close();
            }
            if ui.add_enabled(usable && side == Side::Local && browser.selected.len() == 1, egui::Button::new("Rename"))
                .on_disabled_hover_text("Select one local item. Remote rename is refused because concurrent writers could overwrite another item.").clicked() {
                actions.push(Action::Edit(side, browser.selected.first().cloned())); ui.close();
            }
        };
        if compact_toolbar {
            ui.menu_button("Actions", |ui| {
                operations(ui, actions);
                if side == Side::Local && ui.button("Browse local folder…").clicked() {
                    actions.push(Action::Dialog(DialogRequest::BrowseLocal)); ui.close();
                }
                if ui.button("Edit location").clicked() { browser.show_location = true; ui.close(); }
                if ui.add_enabled(browser.ready, egui::Button::new(if favorites.contains(&browser.path) { "Remove favorite" } else { "Favorite this folder" })).clicked() {
                    actions.push(Action::Favorite(side)); ui.close();
                }
                for path in favorites {
                    if ui.button(path).clicked() { actions.push(Action::Navigate(side, path.clone(), true)); ui.close(); }
                }
            });
        } else { operations(ui, actions); }
        if ui.add_enabled(usable && availability.transfers && !browser.selected.is_empty(), egui::Button::new(if side == Side::Local { "Upload selected" } else { "Download selected" }))
            .on_hover_text(if side == Side::Local { "Upload to the remote folder. Selected folders include their contents." } else { "Download into the local folder. Selected folders include their contents." }).clicked() {
            actions.push(Action::Transfer(side));
        }
    });
    if side == Side::Remote && !availability.daemon {
        ui.colored_label(
            crate::theme::error(ui),
            "Remote actions unavailable. Check daemon compatibility, host identity, and the selected site.",
        );
    }
    if browser.loading {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Loading directory…");
        });
    }
    if let Some(error) = &browser.error {
        ui.colored_label(crate::theme::error(ui), error);
        let lower = error.to_lowercase();
        if lower.contains("mismatch") {
            ui.weak("Security stop. Inspect Device Details and verify the host identity independently before reconnecting.");
        } else if lower.contains("identity")
            || lower.contains("pinned")
            || lower.contains("unverified")
        {
            ui.weak("Open Device Details for the existing host-key trust workflow. Verify the fingerprint independently before pinning it.");
        }
    }
    let compact = ui.available_width() < 510.0;
    let type_width = if ui.available_width() >= 500.0 {
        62.0
    } else {
        0.0
    };
    let date_width = if ui.available_width() < 280.0 {
        0.0
    } else if compact {
        90.0
    } else {
        128.0
    };
    let gaps = 1 + usize::from(type_width > 0.0) + usize::from(date_width > 0.0);
    let widths = [
        (ui.available_width()
            - type_width
            - 75.0
            - date_width
            - ui.spacing().item_spacing.x * gaps as f32)
            .max(70.0),
        type_width,
        75.0,
        date_width,
    ];
    // Horizontal scrolling preserves usable columns in smaller windows.
    egui::ScrollArea::horizontal()
        .id_salt(("file-columns", side == Side::Remote))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                for (index, (label, sort)) in [
                    ("Name", Sort::Name),
                    ("Type", Sort::Type),
                    ("Size", Sort::Size),
                    (
                        if compact { "Date" } else { "Modified (UTC)" },
                        Sort::Modified,
                    ),
                ]
                .into_iter()
                .enumerate()
                {
                    if widths[index] == 0.0 {
                        continue;
                    }
                    let text = if browser.sort == sort {
                        format!(
                            "{label} {}",
                            if browser.descending {
                                "(desc)"
                            } else {
                                "(asc)"
                            }
                        )
                    } else {
                        label.into()
                    };
                    if ui
                        .add_sized([widths[index], 26.0], egui::Button::new(text).truncate())
                        .clicked()
                    {
                        if browser.sort == sort {
                            browser.descending = !browser.descending;
                        } else {
                            browser.sort = sort;
                            browser.descending = false;
                        }
                        browser.anchor = None;
                    }
                }
            });
            let entries: Vec<_> = browser.sorted().into_iter().cloned().collect();
            egui::ScrollArea::vertical()
                .id_salt(("file-rows", side == Side::Remote))
                .max_height(
                    (availability.pane_height - if compact_toolbar { 185.0 } else { 255.0 })
                        .max(70.0),
                )
                .min_scrolled_height(70.0)
                .show_rows(ui, 30.0, entries.len(), |ui, range| {
                    for index in range {
                        let entry = &entries[index];
                        ui.horizontal(|ui| {
                            let selected = browser.selected.contains(&entry.name);
                            let response = ui.add_sized(
                                [widths[0], 30.0],
                                egui::Button::new((RichText::new(&entry.name), egui::Atom::grow()))
                                    .selected(selected)
                                    .frame_when_inactive(selected)
                                    .truncate()
                                    .sense(egui::Sense::click_and_drag()),
                            );
                            if response.clicked() {
                                response.request_focus();
                                let modifiers = ui.input(|i| i.modifiers);
                                if modifiers.shift {
                                    if let Some(anchor) = browser.anchor {
                                        for e in &entries[anchor.min(index)..=anchor.max(index)] {
                                            browser.selected.insert(e.name.clone());
                                        }
                                    } else {
                                        browser.selected.insert(entry.name.clone());
                                    }
                                } else if modifiers.command {
                                    if !browser.selected.remove(&entry.name) {
                                        browser.selected.insert(entry.name.clone());
                                    }
                                } else {
                                    browser.selected.clear();
                                    browser.selected.insert(entry.name.clone());
                                }
                                browser.anchor = Some(index);
                            }
                            if response.has_focus()
                                && ui.input(|i| i.modifiers.command && i.key_pressed(egui::Key::A))
                            {
                                browser
                                    .selected
                                    .extend(entries.iter().map(|e| e.name.clone()));
                            }
                            if (response.double_clicked()
                                || response.has_focus()
                                    && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                                && entry.kind == Kind::Directory
                            {
                                actions.push(Action::Navigate(
                                    side,
                                    format!(
                                        "{}/{}",
                                        browser.path.trim_end_matches('/'),
                                        entry.name
                                    ),
                                    true,
                                ));
                            }
                            if browser.ready && response.drag_started() {
                                let names = if selected {
                                    browser.selected.iter().cloned().collect()
                                } else {
                                    vec![entry.name.clone()]
                                };
                                response.dnd_set_drag_payload(Drag {
                                    side,
                                    device: device.into(),
                                    path: browser.path.clone(),
                                    names,
                                });
                            }
                            if widths[1] > 0.0 {
                                ui.add_sized(
                                    [widths[1], 26.0],
                                    egui::Label::new(entry.kind.label()),
                                );
                            }
                            ui.add_sized(
                                [widths[2], 26.0],
                                egui::Label::new(if entry.kind == Kind::File {
                                    entry
                                        .size
                                        .map(size_text)
                                        .unwrap_or_else(|| "Unknown".into())
                                } else {
                                    "-".into()
                                }),
                            );
                            let date = entry
                                .modified
                                .and_then(|s| chrono::DateTime::from_timestamp(s as i64, 0))
                                .map(|d| {
                                    d.format(if compact {
                                        "%m-%d %H:%M"
                                    } else {
                                        "%Y-%m-%d %H:%M"
                                    })
                                    .to_string()
                                })
                                .unwrap_or_else(|| "Unknown".into());
                            if widths[3] > 0.0 {
                                ui.add_sized([widths[3], 26.0], egui::Label::new(&date));
                            }
                            response.on_hover_text(format!(
                                "{} · {} · Modified (UTC): {date}",
                                entry.name,
                                entry.kind.label()
                            ));
                        });
                    }
                });
        });
    if browser.ready && browser.entries.is_empty() {
        ui.label("This folder is empty.");
    }
    ui.weak(if side == Side::Local {
        "Drop remote items here to download"
    } else {
        "Drop local items here to upload"
    });
    if browser.selected.iter().any(|name| {
        browser
            .entries
            .iter()
            .any(|e| &e.name == name && e.kind == Kind::Directory)
    }) {
        ui.small("Folders include their contents recursively.");
    }
    ui.weak(format!(
        "{} items · {} selected",
        browser
            .entries
            .iter()
            .filter(|e| !lablink_files::fs::is_staging_name(&e.name))
            .count(),
        browser.selected.len()
    ));
}
fn local_home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/".into())
}
fn size_text(size: u64) -> String {
    if size < 1024 {
        format!("{size} B")
    } else if size < 1024 * 1024 {
        format!("{:.1} KiB", size as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", size as f64 / (1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Replace the asynchronous worker receiver so test events are deterministic.
    // Preferences are never marked loaded, so these tests cannot save settings.
    fn workspace() -> (Files, SyncSender<Event>) {
        let mut files = Files::new(
            PathBuf::from("/nonexistent/lablink-files-gui-test.sock"),
            egui::Context::default(),
        );
        let (tx, events) = mpsc::sync_channel(8);
        files.events = events;
        files.device = Some("first-device".into());
        files.local.path = "/nonexistent/first".into();
        files.remote.path = "/remote/first".into();
        (files, tx)
    }

    #[test]
    fn same_named_devices_keep_preferences_and_listing_events_separate() {
        let (mut files, tx) = workspace();
        files.device = Some("home/device".into());
        files
            .preferences
            .devices
            .entry("lab/device".into())
            .or_default()
            .remote = Some("/lab".into());
        files
            .preferences
            .devices
            .entry("home/device".into())
            .or_default()
            .remote = Some("/home".into());
        for (device, path) in [("lab/device", "/stale-lab"), ("home/device", "/new-home")] {
            tx.send(Event::Listed {
                generation: files.remote.generation,
                device: device.into(),
                side: Side::Remote,
                result: Ok(Listing {
                    path: path.into(),
                    entries: vec![],
                }),
            })
            .unwrap();
        }
        files.drain();
        assert_eq!(files.remote.path, "/new-home");
        assert_eq!(
            files.preferences.devices["lab/device"].remote.as_deref(),
            Some("/lab")
        );
        assert_eq!(
            files.preferences.devices["home/device"].remote.as_deref(),
            Some("/new-home")
        );
        assert!(!files.preferences.devices.contains_key("device"));
    }

    #[test]
    fn same_named_devices_keep_queued_dialog_transfers_qualified() {
        let (mut files, _) = workspace();
        files.device = Some("home/device".into());
        for (device, remote) in [("lab/device", "/lab"), ("home/device", "/home")] {
            files
                .dialog_tx
                .send(DialogResult {
                    device: device.into(),
                    remote: remote.into(),
                    request: DialogRequest::UploadFiles,
                    paths: vec![PathBuf::from("/nonexistent/source.txt")],
                })
                .unwrap();
        }
        files.drain();
        assert_eq!(files.queue.len(), 2);
        assert_eq!(files.queue[0].job.device, "lab/device");
        assert_eq!(files.queue[0].job.remote, "/lab");
        assert_eq!(files.queue[1].job.device, "home/device");
        assert_eq!(files.queue[1].job.remote, "/home");
    }

    #[test]
    fn local_listing_survives_missing_files_daemon_capability() {
        let (mut files, tx) = workspace();
        files.daemon_available = false;
        tx.send(Event::Listed {
            generation: files.local.generation,
            device: "first-device".into(),
            side: Side::Local,
            result: Ok(Listing {
                path: "/local".into(),
                entries: vec![],
            }),
        })
        .unwrap();
        files.drain();
        assert!(files.local.ready);
        assert_eq!(files.local.path, "/local");
        assert!(!files.transfers_ready());
    }

    #[test]
    fn navigation_cancels_edit_in_original_pane() {
        let (mut files, _) = workspace();
        for old in [None, Some("original.txt".into())] {
            files.edit = Some(EditDialog {
                focus: true,
                side: Side::Local,
                old,
                name: "new-name".into(),
            });
            files.navigate(Side::Local, "/nonexistent/second".into(), true);
            assert!(files.edit.is_none());
            assert!(files.notice.as_ref().unwrap().contains("cancelled"));
        }
    }

    #[test]
    fn other_pane_navigation_preserves_edit() {
        let (mut files, _) = workspace();
        files.edit = Some(EditDialog {
            focus: true,
            side: Side::Local,
            old: None,
            name: "new-folder".into(),
        });
        files.navigate(Side::Remote, "/remote/second".into(), true);
        assert!(files.edit.is_some());
    }

    #[test]
    fn transfers_require_both_listings_and_daemon() {
        let (mut files, _) = workspace();
        for daemon in [false, true] {
            for local in [false, true] {
                for remote in [false, true] {
                    files.daemon_available = daemon;
                    files.local.ready = local;
                    files.remote.ready = remote;
                    assert_eq!(files.transfers_ready(), daemon && local && remote);
                }
            }
        }
    }

    #[test]
    fn old_daemon_error_is_visible_and_prevents_transfer() {
        let (mut files, tx) = workspace();
        files.daemon_available = true;
        files.local.ready = true;
        tx.send(Event::Listed {
            generation: files.remote.generation,
            device: "first-device".into(),
            side: Side::Remote,
            result: Err(
                "Files is unavailable in this daemon version; run the matching feature daemon"
                    .into(),
            ),
        })
        .unwrap();
        files.drain();
        assert!(!files.transfers_ready());
        assert!(files
            .remote
            .error
            .as_ref()
            .unwrap()
            .contains("matching feature daemon"));
        assert!(files.local.ready);
    }

    #[test]
    fn upload_dialog_keeps_original_device_and_destination() {
        let (mut files, _tx) = workspace();
        files.device = Some("second-device".into());
        files.remote.path = "/remote/second".into();
        files
            .dialog_tx
            .send(DialogResult {
                device: "first-device".into(),
                remote: "/remote/first".into(),
                request: DialogRequest::UploadFiles,
                paths: vec![PathBuf::from("/nonexistent/source.txt")],
            })
            .unwrap();
        files.drain();
        assert_eq!(files.queue.len(), 1);
        let job = &files.queue[0].job;
        assert_eq!(job.device, "first-device");
        assert_eq!(job.remote, "/remote/first");
        assert_eq!(job.local, PathBuf::from("/nonexistent/source.txt"));
    }

    #[test]
    fn download_dialog_keeps_original_sources_and_destination() {
        let (mut files, _tx) = workspace();
        files.device = Some("second-device".into());
        files.remote.path = "/remote/second".into();
        files
            .dialog_tx
            .send(DialogResult {
                device: "first-device".into(),
                remote: "/remote/first".into(),
                request: DialogRequest::Download(vec!["/remote/first/source.txt".into()]),
                paths: vec![PathBuf::from("/nonexistent/download-destination")],
            })
            .unwrap();
        files.drain();
        assert_eq!(files.queue.len(), 1);
        let job = &files.queue[0].job;
        assert_eq!(job.device, "first-device");
        assert_eq!(job.remote, "/remote/first/source.txt");
        assert_eq!(
            job.local,
            PathBuf::from("/nonexistent/download-destination")
        );
    }

    #[test]
    fn local_browse_dialog_does_not_navigate_new_device() {
        let (mut files, _tx) = workspace();
        files.device = Some("second-device".into());
        files
            .dialog_tx
            .send(DialogResult {
                device: "first-device".into(),
                remote: "/remote/first".into(),
                request: DialogRequest::BrowseLocal,
                paths: vec![PathBuf::from("/nonexistent/different")],
            })
            .unwrap();
        let generation = files.local.generation;
        files.drain();
        assert_eq!(files.local.generation, generation);
        assert_eq!(files.local.path, "/nonexistent/first");
    }
}
