//! `lablinkd` binary.

use clap::Parser;
use lablink_core::config::Config;
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(
    name = "lablinkd",
    version,
    about = "LabLink daemon: device discovery, SSH health and identity tracking"
)]
struct Args {
    /// Configuration file [default: $XDG_CONFIG_HOME/lablink/config.yaml]
    #[arg(long, short)]
    config: Option<PathBuf>,
    /// Unix socket path [default: $XDG_RUNTIME_DIR/lablink/lablinkd.sock]
    #[arg(long)]
    socket: Option<PathBuf>,
    /// State directory (cache DB, pinned known_hosts) [default: $XDG_STATE_HOME/lablink]
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// Log filter (error, warn, info, debug, trace, or a tracing directive). Overrides LABLINK_LOG.
    #[arg(long)]
    log: Option<String>,
    /// Emit logs without ANSI colors (default when stderr is not a terminal).
    #[arg(long)]
    no_color: bool,
    /// Disable the rtnetlink monitor.
    #[arg(long)]
    no_netlink: bool,
    /// Disable mDNS regardless of the config file.
    #[arg(long)]
    no_mdns: bool,
    /// Skip the discovery pass at startup.
    #[arg(long)]
    no_startup_discovery: bool,
    /// Validate the configuration and exit.
    #[arg(long)]
    check_config: bool,
}

fn main() {
    let args = Args::parse();
    let filter = args
        .log
        .clone()
        .or_else(|| std::env::var("LABLINK_LOG").ok())
        .unwrap_or_else(|| "info".into());
    // Default level `info` logs only state transitions and lifecycle events.
    let directive = if filter.contains('=') {
        filter.clone()
    } else {
        format!("warn,lablink_daemon={filter},lablinkd={filter},lablink_discovery={filter}")
    };
    let ansi = !args.no_color && std::io::IsTerminal::is_terminal(&std::io::stderr());
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&directive)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(ansi)
        .with_target(false)
        .init();

    let config_path = args
        .config
        .clone()
        .unwrap_or_else(lablink_core::paths::default_config_path);
    let config = if config_path.exists() {
        match Config::load(&config_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("lablinkd: {e}");
                std::process::exit(lablink_core::exit::USAGE);
            }
        }
    } else {
        if args.config.is_some() {
            eprintln!(
                "lablinkd: config file {} does not exist",
                config_path.display()
            );
            std::process::exit(lablink_core::exit::USAGE);
        }
        tracing::warn!(path = %config_path.display(), "no config file; running with no devices or networks");
        Config::default()
    };
    if args.check_config {
        println!(
            "{}: OK ({} sites, {} networks, {} devices)",
            config_path.display(),
            config.sites.len(),
            config.network_count(),
            config.device_count()
        );
        return;
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(8)
        .thread_keep_alive(std::time::Duration::from_secs(10))
        .build();
    let rt = match rt {
        Ok(r) => r,
        Err(e) => {
            eprintln!("lablinkd: cannot start runtime: {e}");
            std::process::exit(lablink_core::exit::FAILURE);
        }
    };
    let cancel = CancellationToken::new();
    let result = rt.block_on(async {
        let c = cancel.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let (Ok(mut term), Ok(mut int), Ok(mut hup)) =
                (signal(SignalKind::terminate()), signal(SignalKind::interrupt()), signal(SignalKind::hangup()))
            else {
                tracing::error!("cannot install signal handlers");
                return;
            };
            loop {
                tokio::select! {
                    _ = term.recv() => { tracing::info!("SIGTERM received"); break; }
                    _ = int.recv() => { tracing::info!("SIGINT received"); break; }
                    _ = hup.recv() => { tracing::info!("SIGHUP ignored: restart the service to reload the configuration"); }
                }
            }
            c.cancel();
        });
        lablink_daemon::run(lablink_daemon::RunOptions {
            config,
            socket: args.socket.unwrap_or_else(lablink_core::paths::default_socket_path),
            state_dir: args.state_dir.unwrap_or_else(lablink_core::paths::default_state_dir),
            netlink: !args.no_netlink,
            mdns: !args.no_mdns,
            startup_discovery: !args.no_startup_discovery,
            prober: None,
            cancel: cancel.clone(),
            ready: None,
        })
        .await
    });
    if let Err(e) = result {
        eprintln!("lablinkd: {e}");
        std::process::exit(lablink_core::exit::FAILURE);
    }
}
