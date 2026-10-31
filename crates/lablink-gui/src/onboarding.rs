//! GUI SSH onboarding. No password widget, terminal capture or shell commands.
use crate::{term, view};
use eframe::egui::{self, RichText};
use lablink_core::client::Client;
use lablink_core::model::{DiscoveredHost, TrustReport};
use lablink_core::protocol::{DeviceChanges, Request};
use lablink_core::site::{SiteState, SiteStatus};
use lablink_setup::onboarding::{self as setup, Plan, Progress, Session};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Details,
    Finding,
    Identity,
    Pinning,
    Key,
    Authentication,
    Testing,
    Name,
    Saving,
    Done,
}

enum Event {
    Adopted(String),
    Preview(Result<TrustReport, String>),
    Pinned(Result<TrustReport, String>),
    Progress(Progress),
    TerminalDone(Progress, Option<PathBuf>),
    Saved(Result<(), String>),
}

pub struct Onboarding {
    pub page: Page,
    pub ip: String,
    pub username: String,
    pub site: Option<String>,
    device: Option<String>,
    known_host: bool,
    preview: Option<TrustReport>,
    pub verified: bool,
    pub identity: String,
    pub create_key: bool,
    pub consent: bool,
    pub friendly: String,
    pub error: Option<String>,
    tx: mpsc::Sender<Event>,
    rx: mpsc::Receiver<Event>,
    cancel: Arc<AtomicBool>,
    finished: bool,
}
impl Drop for Onboarding {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}
impl Onboarding {
    pub fn new(host: Option<&DiscoveredHost>, site: Option<String>) -> Self {
        let (tx, rx) = mpsc::channel();
        let identity = setup::existing_identity();
        Self {
            page: Page::Details,
            ip: host.map(|h| h.ip.clone()).unwrap_or_default(),
            username: String::new(),
            site,
            device: host.and_then(|h| h.matched_device.clone()),
            known_host: host.is_some(),
            preview: None,
            verified: false,
            create_key: identity.is_none(),
            identity: identity
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            consent: false,
            friendly: String::new(),
            error: None,
            tx,
            rx,
            cancel: Arc::new(AtomicBool::new(false)),
            finished: false,
        }
    }
    pub fn for_device(device: &lablink_core::model::DeviceStatus) -> Self {
        let mut w = Self::new(None, Some(device.site.clone()));
        w.ip = device.ip.clone().unwrap_or_default();
        w.device = Some(device.id.clone());
        w.username = device.username.clone().unwrap_or_default();
        w.known_host = true;
        w
    }
    fn details_error(&self, sites: &[SiteStatus]) -> Option<String> {
        if self.ip.parse::<std::net::IpAddr>().is_err() {
            return Some("Enter a valid IP address.".into());
        }
        if !lablink_core::config::valid_username(self.username.trim()) {
            return Some("Enter the device's SSH login username.".into());
        }
        if !sites
            .iter()
            .any(|s| Some(&s.id) == self.site.as_ref() && s.state == SiteState::Active)
        {
            return Some(
                "Select the active site for this network. Away sites cannot be onboarded here."
                    .into(),
            );
        }
        None
    }
    fn prepare(&mut self, socket: PathBuf, ctx: egui::Context) {
        self.error = None;
        self.page = Page::Finding;
        self.verified = false;
        let (ip, username, site, device, known) = (
            self.ip.trim().to_string(),
            self.username.trim().to_string(),
            self.site.clone().unwrap(),
            self.device.clone(),
            self.known_host,
        );
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let c = Client::new(socket).with_timeout(Duration::from_secs(150));
            let r = (|| -> Result<TrustReport, String> {
                // Re-check live site state rather than trusting the GUI's cache.
                let sites: lablink_core::site::SitesReport =
                    c.call_typed(&Request::Sites).map_err(|e| e.to_string())?;
                if !sites
                    .sites
                    .iter()
                    .any(|s| s.id == site && s.state == SiteState::Active)
                {
                    return Err(
                        "This site is no longer active. Select the site for the current network."
                            .into(),
                    );
                }
                let id = if let Some(id) = device {
                    if id.split_once('/').map(|p| p.0) != Some(&site) {
                        return Err("This device belongs to a different site. Its trust and credentials were kept.".into());
                    }
                    id
                } else {
                    if !known {
                        let addr: std::net::Ipv4Addr = ip.parse().map_err(|_| "Manual discovery currently supports private, directly attached IPv4 addresses. Select an already discovered host for IPv6.".to_string())?;
                        c.call(&Request::Discover {
                            scan_cidr: Some(format!("{addr}/32")),
                        })
                        .map_err(|e| e.to_string())?;
                    }
                    let list = c.call(&Request::Discovered).map_err(|e| e.to_string())?;
                    let hosts: Vec<DiscoveredHost> =
                        serde_json::from_value(list["discovered"].clone())
                            .map_err(|_| "Could not read discovered devices.")?;
                    let h = hosts.iter().find(|h| h.ip == ip).ok_or(
                        "Device unavailable. Check the IP address and network, then retry.",
                    )?;
                    if h.site.as_ref().is_some_and(|s| s != &site) {
                        return Err(
                            "The device was discovered at another site. Select the correct site."
                                .into(),
                        );
                    }
                    if let Some(id) = &h.matched_device {
                        if id.split_once('/').map(|p| p.0) != Some(&site) {
                            return Err("This device is already tracked at another site.".into());
                        }
                        id.clone()
                    } else {
                        // A logical identifier is allocated before authentication;
                        // the user chooses the friendly display name after success.
                        let name = format!("device-{}", ip.replace(['.', ':'], "-"));
                        let d: lablink_core::model::DeviceStatus = c
                            .call_typed(&Request::Adopt {
                                ip: ip.clone(),
                                name,
                                label: None,
                                username: Some(username.clone()),
                                profile: None,
                                ssh: Some(true),
                                site: Some(site.clone()),
                            })
                            .map_err(|e| e.to_string())?;
                        d.id
                    }
                };
                let _ = tx.send(Event::Adopted(id.clone()));
                ctx.request_repaint();
                c.call(&Request::Set {
                    device: id.clone(),
                    changes: DeviceChanges {
                        username: Some(username),
                        ..Default::default()
                    },
                })
                .map_err(|e| e.to_string())?;
                c.call_typed(&Request::Trust {
                    device: id,
                    confirm: None,
                    replace: false,
                })
                .map_err(|e| e.to_string())
            })();
            let _ = tx.send(Event::Preview(r));
            ctx.request_repaint();
        });
    }
    fn pin(&mut self, socket: PathBuf, ctx: egui::Context) {
        let Some(p) = self
            .preview
            .as_ref()
            .filter(|p| can_confirm(p, self.verified))
        else {
            return;
        };
        self.page = Page::Pinning;
        self.error = None;
        let request = Request::Trust {
            device: p.device.clone(),
            confirm: Some(p.scanned.iter().map(|k| k.fingerprint.clone()).collect()),
            replace: false,
        };
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let r = Client::new(socket)
                .call_typed(&request)
                .map_err(|e| e.to_string());
            let _ = tx.send(Event::Pinned(r));
            ctx.request_repaint();
        });
    }
    fn authenticate(&mut self, socket: PathBuf, preferred: Option<&str>, ctx: egui::Context) {
        let Some(p) = self
            .preview
            .as_ref()
            .filter(|p| can_confirm(p, self.verified))
        else {
            return;
        };
        let plan = Plan {
            device: p.device.clone(),
            username: self.username.trim().to_string(),
            fingerprints: p.scanned.iter().map(|k| k.fingerprint.clone()).collect(),
            identity: (!self.create_key).then(|| PathBuf::from(self.identity.trim())),
            generate_consent: self.create_key && self.consent,
        };
        let r = (|| {
            let session = Session::new(&plan)?;
            let terminal = term::onboarding_terminal(preferred)?;
            let cmd = term::onboarding_command(
                &terminal,
                &term::onboarding_binary()?,
                &socket,
                session.path(),
            )?;
            Ok::<_, String>((session, cmd))
        })();
        let (session, mut cmd) = match r {
            Ok(r) => r,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let tx = self.tx.clone();
        self.page = Page::Authentication;
        self.error = None;
        std::thread::spawn(move || {
            let result = (|| -> Result<Progress, String> {
                let mut child = cmd
                    .spawn()
                    .map_err(|_| "Could not open the authentication terminal.".to_string())?;
                let deadline = Instant::now() + Duration::from_secs(16 * 60);
                let mut previous = Progress::Waiting;
                loop {
                    if cancel.load(Ordering::Acquire) || Instant::now() > deadline {
                        session.cancel();
                    }
                    if let Some(p) = session.progress() {
                        if p != previous {
                            previous = p;
                            let _ = tx.send(Event::Progress(p));
                            ctx.request_repaint();
                        }
                    }
                    if child
                        .try_wait()
                        .map_err(|_| "Cannot monitor the terminal.".to_string())?
                        .is_some()
                    {
                        // A success record, rather than the terminal emulator's
                        // exit status, proves that both installation and test ran.
                        return Ok(session
                            .progress()
                            .filter(|p| p.finished())
                            .unwrap_or(Progress::Cancelled));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            })();
            let progress = result.unwrap_or(Progress::Unavailable);
            let _ = tx.send(Event::TerminalDone(
                progress,
                setup::generated_identity(session.path()),
            ));
            ctx.request_repaint();
        });
    }
    fn events(&mut self) {
        while let Ok(e) = self.rx.try_recv() {
            match e {
                Event::Adopted(id) => {
                    self.device = Some(id);
                    self.known_host = true;
                }
                Event::Preview(r) => match r {
                    Ok(p) => {
                        self.preview = Some(p);
                        self.page = Page::Identity;
                    }
                    Err(e) => {
                        self.error = Some(e);
                        self.page = Page::Details;
                    }
                },
                Event::Pinned(r) => match r {
                    Ok(_) => self.page = Page::Key,
                    Err(e) => {
                        self.error = Some(e);
                        self.verified = false;
                        self.page = Page::Identity;
                    }
                },
                Event::Progress(Progress::Testing) if self.page == Page::Authentication => {
                    self.page = Page::Testing
                }
                Event::Progress(_) => {}
                Event::TerminalDone(p, path) => {
                    if let Some(path) = path {
                        self.identity = path.display().to_string();
                        self.create_key = false;
                        self.consent = false;
                    }
                    if p == Progress::Connected {
                        self.page = Page::Name;
                    } else {
                        self.page = Page::Key;
                        self.error = Some(p.message().into());
                    }
                }
                Event::Saved(r) => match r {
                    Ok(()) => {
                        self.page = Page::Done;
                        self.finished = true;
                    }
                    Err(e) => {
                        self.page = Page::Name;
                        self.error = Some(e);
                    }
                },
            }
        }
    }
    /// Returns true on close; callers refresh device status afterwards.
    pub fn show(
        &mut self,
        ctx: &egui::Context,
        socket: &std::path::Path,
        sites: &[SiteStatus],
        terminal: Option<&str>,
    ) -> bool {
        self.events();
        let mut close = false;
        egui::Window::new("Connect a device securely").id(egui::Id::new("ssh_onboarding"))
            .collapsible(false).resizable(false).default_width(570.0).default_pos(egui::pos2(110.0, 90.0)).show(ctx, |ui| {
                let current = match self.page {
                    Page::Details | Page::Finding => 0,
                    Page::Identity | Page::Pinning => 1,
                    Page::Key | Page::Authentication => 2,
                    Page::Testing => 3,
                    _ => 4,
                };
                for (index, label) in ["Discovering device", "Verifying device identity", "Configuring authentication", "Testing connection", "Connected"].iter().enumerate() {
                    let text = format!("{}. {}{}", index + 1, label, if index < current { " · complete" } else { "" });
                    if index == current {
                        ui.label(RichText::new(text).strong().color(egui::Color32::from_rgb(97, 175, 239)));
                    } else {
                        ui.label(text);
                    }
                }
                ui.separator();
                if let Some(e) = &self.error { ui.colored_label(view::RED, e); ui.add_space(8.0); }
                match self.page {
                    Page::Details => {
                        ui.label("Choose the site and SSH username for this device.");
                        egui::ComboBox::from_id_salt("ssh_site").selected_text(sites.iter().find(|s| Some(&s.id) == self.site.as_ref()).map(|s| s.name.as_str()).unwrap_or("Select a site"))
                            .show_ui(ui, |ui| { for s in sites { ui.add_enabled_ui(s.state == SiteState::Active && self.device.is_none(), |ui| { ui.selectable_value(&mut self.site, Some(s.id.clone()), &s.name); }); } });
                        ui.label("IP address");
                        ui.add_enabled(self.device.is_none(), egui::TextEdit::singleline(&mut self.ip));
                        ui.label("SSH username"); ui.text_edit_singleline(&mut self.username);
                        ui.weak("Home and Lab are separate sites. Use the site active on this network.");
                        let err = self.details_error(sites);
                        if let Some(e) = &err { ui.weak(e); }
                        if ui.add_enabled(err.is_none(), egui::Button::new("Continue")).clicked() { self.prepare(socket.to_path_buf(), ctx.clone()); }
                    }
                    Page::Identity => {
                        if let Some(p) = &self.preview {
                            ui.strong("Verify this device independently");
                            ui.label(format!("{} · {}", self.site.as_deref().unwrap_or(""), p.ip));
                            for k in &p.scanned { ui.label(&k.key_type); ui.monospace(&k.fingerprint); }
                            ui.label("Compare every fingerprint with the device's own console or a trusted administrator. A fingerprint shown here alone does not establish identity.");
                            ui.collapsing("How to find the fingerprint on the device", |ui| { ui.label("On the device's local console, display its SSH host-key fingerprints:"); ui.monospace("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"); ui.label("For other key types, use their matching host public-key files."); });
                            let mismatch = pins_conflict(p);
                            if mismatch { ui.colored_label(view::RED, "Security stop: these keys conflict with existing pins. Onboarding cannot replace trusted identities."); }
                            ui.checkbox(&mut self.verified, "I independently verified every fingerprint above.");
                            if ui.add_enabled(can_confirm(p, self.verified), egui::Button::new("Confirm identity and continue")).clicked() { self.pin(socket.to_path_buf(), ctx.clone()); }
                        }
                    }
                    Page::Key => {
                        ui.strong("Configure SSH authentication");
                        ui.label("LabLink opens a real terminal. Enter your SSH password directly into OpenSSH there. LabLink never reads or stores it.");
                        ui.radio_value(&mut self.create_key, false, "Use an existing SSH key");
                        if !self.create_key { ui.collapsing("Choose a different SSH key", |ui| { ui.label("Private-key path (the public .pub file must also exist)"); ui.text_edit_singleline(&mut self.identity); }); }
                        ui.radio_value(&mut self.create_key, true, "Create a new SSH key");
                        if self.create_key { ui.checkbox(&mut self.consent, "I agree to create a new key in a fresh private folder inside ~/.ssh."); ui.weak("OpenSSH will ask you for a key passphrase in the terminal. Existing keys are kept."); }
                        if ui.add_enabled(!self.create_key || self.consent, egui::Button::new("Open authentication terminal")).clicked() { self.authenticate(socket.to_path_buf(), terminal, ctx.clone()); }
                        if ui.button("Change username / verify again").clicked() { self.page = Page::Details; self.error = None; self.verified = false; }
                    }
                    Page::Authentication | Page::Testing => { ui.spinner(); ui.label(if self.page == Page::Testing { Progress::Testing.message() } else { Progress::Configuring.message() }); ui.weak("Keep the terminal open until the connection test finishes."); if ui.button("Cancel authentication").clicked() { self.cancel.store(true, Ordering::Release); } }
                    Page::Name => {
                        ui.colored_label(view::GREEN, Progress::Connected.message());
                        ui.label("Give this device a friendly name"); ui.text_edit_singleline(&mut self.friendly);
                        let valid = lablink_core::config::valid_display_name(self.friendly.trim());
                        if ui.add_enabled(valid, egui::Button::new("Save device")).clicked() {
                            self.page = Page::Saving; self.error = None;
                            let tx = self.tx.clone(); let c = Client::new(socket); let ctx = ctx.clone();
                            let device = self.device.clone().unwrap(); let label = self.friendly.trim().to_string();
                            std::thread::spawn(move || { let r = c.call(&Request::Set { device, changes: DeviceChanges { label: Some(label), ..Default::default() }}).map(|_| ()).map_err(|e| e.to_string()); let _ = tx.send(Event::Saved(r)); ctx.request_repaint(); });
                        }
                    }
                    Page::Done => { ui.colored_label(view::GREEN, format!("{} is connected at {}.", self.friendly, self.site.as_deref().unwrap_or(""))); ui.label(format!("Device reference: {}", self.device.as_deref().unwrap_or(""))); if ui.button("Done").clicked() { close = true; } }
                    _ => { ui.spinner(); ui.label(match self.page { Page::Finding => "Discovering device and checking its SSH identity…", Page::Pinning => "Rechecking and pinning the exact fingerprints you approved…", _ => "Saving your device…" }); }
                }
                ui.separator();
                if !matches!(self.page, Page::Authentication | Page::Testing | Page::Saving | Page::Done) && ui.button("Close setup").clicked() { close = true; }
                if self.device.is_some() && !self.finished { ui.weak("If setup is interrupted, the device stays tracked for retry. Approved pins and installed keys are retained."); }
            });
        close
    }
}

pub fn pins_conflict(p: &TrustReport) -> bool {
    !p.pinned_before.is_empty()
        && p.scanned.iter().any(|k| {
            !p.pinned_before
                .iter()
                .any(|old| old.fingerprint == k.fingerprint)
        })
}
pub fn can_confirm(p: &TrustReport, independently_verified: bool) -> bool {
    independently_verified && !p.scanned.is_empty() && !pins_conflict(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lablink_core::model::KeyView;
    fn report() -> TrustReport {
        TrustReport {
            schema_version: 1,
            device: "home/device".into(),
            ip: "10.9.0.5".into(),
            action: "preview".into(),
            scanned: vec![KeyView {
                key_type: "ssh-ed25519".into(),
                fingerprint: "SHA256:approved".into(),
                source: None,
            }],
            pinned_before: vec![],
            pinned_now: vec![],
        }
    }
    #[test]
    fn first_use_and_existing_trust_both_need_independent_confirmation() {
        let mut r = report();
        assert!(!can_confirm(&r, false));
        assert!(can_confirm(&r, true));
        r.pinned_before = r.scanned.clone();
        assert!(!can_confirm(&r, false));
        assert!(can_confirm(&r, true));
        r.pinned_before[0].fingerprint = "SHA256:old".into();
        assert!(!can_confirm(&r, true));
        r.scanned.clear();
        assert!(!can_confirm(&r, true));
    }
    #[test]
    fn state_machine_runs_identity_authentication_test_then_naming() {
        let mut w = Onboarding::new(None, Some("home".into()));
        w.page = Page::Finding;
        w.tx.send(Event::Adopted("home/device".into())).unwrap();
        w.tx.send(Event::Preview(Ok(report()))).unwrap();
        w.events();
        assert_eq!(w.page, Page::Identity);
        assert!(!w.verified);
        w.verified = true;
        w.page = Page::Pinning;
        w.tx.send(Event::Pinned(Ok(report()))).unwrap();
        w.events();
        assert_eq!(w.page, Page::Key);
        w.page = Page::Authentication;
        w.tx.send(Event::Progress(Progress::Testing)).unwrap();
        w.events();
        assert_eq!(w.page, Page::Testing);
        w.tx.send(Event::TerminalDone(Progress::Connected, None))
            .unwrap();
        w.events();
        assert_eq!(w.page, Page::Name);
        w.tx.send(Event::Saved(Ok(()))).unwrap();
        w.events();
        assert_eq!(w.page, Page::Done);
    }
    #[test]
    fn auth_cancellation_password_username_and_server_failures_can_retry() {
        for result in [
            Progress::Cancelled,
            Progress::AuthenticationFailed,
            Progress::TestFailed,
            Progress::Unavailable,
            Progress::IdentityFailed,
        ] {
            let mut w = Onboarding::new(None, Some("home".into()));
            w.page = Page::Authentication;
            w.device = Some("home/device".into());
            w.tx.send(Event::TerminalDone(result, None)).unwrap();
            w.events();
            assert_eq!(w.page, Page::Key);
            assert!(w.error.is_some());
            assert_eq!(w.site.as_deref(), Some("home"));
            assert_eq!(w.device.as_deref(), Some("home/device"));
        }
    }
    #[test]
    fn preview_pin_and_save_failures_do_not_skip_required_stages() {
        let mut w = Onboarding::new(None, Some("home".into()));
        w.tx.send(Event::Preview(Err("unreachable".into())))
            .unwrap();
        w.events();
        assert_eq!(w.page, Page::Details);
        w.verified = true;
        w.tx.send(Event::Pinned(Err("key changed".into()))).unwrap();
        w.events();
        assert_eq!(w.page, Page::Identity);
        assert!(!w.verified);
        w.tx.send(Event::Saved(Err("offline".into()))).unwrap();
        w.events();
        assert_eq!(w.page, Page::Name);
    }
    #[test]
    fn dropping_the_wizard_cancels_the_terminal_job() {
        let w = Onboarding::new(None, Some("home".into()));
        let cancel = w.cancel.clone();
        drop(w);
        assert!(cancel.load(Ordering::Acquire));
    }
}
