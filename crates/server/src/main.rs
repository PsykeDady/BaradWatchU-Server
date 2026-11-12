use baradwatchu_server::{config::Config, launcher};
use std::{io, process::ExitCode};

/// What the command line asked for.
#[derive(Debug, PartialEq)]
enum Start {
    /// Informational/provisioning command already handled.
    Done,
    /// Plain start: serve; never opens a browser.
    Serve,
    /// `dashboard [--no-browser]`: reuse a live session or start one, like the Client.
    Dashboard { open_browser: bool },
}

fn main() -> ExitCode {
    let start_mode = match handle_cli() {
        Ok(Start::Done) => return ExitCode::SUCCESS,
        Ok(mode) => mode,
        Err(error) => {
            eprintln!("Error: {error}");
            return ExitCode::from(2);
        }
    };
    match start(start_mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn runtime() -> io::Result<tokio::runtime::Runtime> {
    // A manually built Tokio runtime must explicitly enable its I/O drivers.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
}

fn start(mode: Start) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let open_browser = mode == (Start::Dashboard { open_browser: true });
    let local = config.settings.auth_mode == baradwatchu_server::config::AuthMode::Local;
    if local && matches!(mode, Start::Dashboard { .. }) {
        let dir = launcher::runtime_dir()?;
        if let Some(session) = launcher::read_session(&dir).filter(launcher::session_alive) {
            let language = baradwatchu_messages::configured_language();
            println!(
                "{}",
                baradwatchu_messages::message("cli.dashboard.already_running", language)
                    .replace("{url}", &session.url())
                    .trim_end()
            );
            if open_browser {
                launcher::open_in_browser(&dir, &session.url());
            }
            return Ok(());
        }
    }
    runtime()?.block_on(run_server(config, open_browser))?;
    Ok(())
}

async fn run_server(config: Config, open_browser: bool) -> io::Result<()> {
    let listener = tokio::net::TcpListener::bind(config.address).await.map_err(|error| {
        io::Error::new(error.kind(), format!("cannot listen on {}: {error}; check the address, port availability and permissions", config.address))
    })?;
    let address = listener.local_addr()?;
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    println!(
        "BaradWatchU Server {} listening on http://{address}",
        env!("CARGO_PKG_VERSION")
    );
    let shutdown = async move {
        #[cfg(unix)]
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
        }
        #[cfg(not(unix))]
        if let Err(error) = tokio::signal::ctrl_c().await {
            eprintln!("Error waiting for shutdown signal: {error}");
        }
        println!("BaradWatchU Server shutting down");
    };
    let settings = config.settings;
    if !settings.web_path().join("index.html").is_file() {
        return Err(io::Error::other(
            "dashboard assets missing; rebuild/reinstall the Server or configure webDir",
        ));
    }
    let store = baradwatchu_server::storage::Store::open(
        &baradwatchu_server::config::data_dir().map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)?;
    let origin = settings.origin().to_owned();
    let app = baradwatchu_server::http::App::with_listen_address(store, settings, Some(address))
        .map_err(io::Error::other)?;
    let tunnel_address: std::net::SocketAddr = std::env::var("BARADWATCHU_SERVER_TUNNEL_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:7445".into())
        .parse()
        .map_err(|_| io::Error::other("invalid BARADWATCHU_SERVER_TUNNEL_ADDR"))?;
    baradwatchu_server::tunnel::listen(app.clone(), tunnel_address).map_err(io::Error::other)?;
    println!("Client tunnel listening on {tunnel_address}");
    // LOCAL: publish the launch token only in the owner's private runtime folder (Client model).
    let runtime = match app.launch_token() {
        Some(token) => {
            let dir = launcher::runtime_dir().map_err(io::Error::other)?;
            let session = launcher::Session {
                schema_version: launcher::SESSION_SCHEMA.into(),
                pid: std::process::id(),
                origin: origin.clone(),
                port: address.port(),
                token: token.to_owned(),
            };
            launcher::write_session(&dir, &session).map_err(io::Error::other)?;
            Some((dir, session.url()))
        }
        None => None,
    };
    let url = runtime
        .as_ref()
        .map_or_else(|| origin.clone(), |(_, url)| url.clone());
    let language = baradwatchu_messages::configured_language();
    println!(
        "{}",
        baradwatchu_messages::message("cli.dashboard.started", language)
            .replace("{url}", &url)
            .trim_end()
    );
    if open_browser {
        match &runtime {
            Some((dir, url)) => launcher::open_in_browser(dir, url),
            None => {
                // OIDC: the public origin carries no secret; still use the private launcher.
                if let Ok(dir) = launcher::runtime_dir() {
                    launcher::open_in_browser(&dir, &url);
                }
            }
        }
    }
    let result = axum::serve(listener, baradwatchu_server::http::application(app))
        .with_graceful_shutdown(shutdown)
        .await;
    if let Some((dir, _)) = &runtime {
        launcher::remove_session(dir);
    }
    result
}

/// Parse the command line; informational flags start no runtime.
fn handle_cli() -> Result<Start, String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|s| s == "setup") {
        let values: Vec<String> = args
            .iter()
            .skip(1)
            .map(|s| {
                s.to_str()
                    .map(str::to_owned)
                    .ok_or("invalid setup argument")
            })
            .collect::<Result<_, _>>()?;
        provision(&values)?;
        return Ok(Start::Done);
    }
    parse_start(&args)
}

fn parse_start(args: &[std::ffi::OsString]) -> Result<Start, String> {
    match args {
        [] => Ok(Start::Serve),
        [command] if command == "dashboard" => Ok(Start::Dashboard { open_browser: true }),
        [command, flag] if command == "dashboard" && flag == "--no-browser" => {
            Ok(Start::Dashboard {
                open_browser: false,
            })
        }
        [flag] if flag == "--version" || flag == "-V" => {
            println!("BaradWatchU Server {}", env!("CARGO_PKG_VERSION"));
            Ok(Start::Done)
        }
        [flag] if flag == "--help" || flag == "-h" => {
            println!(
                "BaradWatchU Server {}\n\nUsage: baradwatchu-server [dashboard [--no-browser] | OPTIONS]\n\nOptions:\n  -h, --help       Show this help and exit\n  -V, --version    Show product version and exit\n\nStart without arguments (no browser) or with dashboard, which reuses a running\nLOCAL Server of this user or starts one and opens the browser; keep it running.\nWithout server.json, the full dashboard uses LOCAL authentication on loopback:\nthe launch link carries a random token stored only in\n$XDG_RUNTIME_DIR/baradwatchu-server/dashboard.json (owner-only).\nConfiguration: BARADWATCHU_SERVER_CONFIG, /etc/baradwatchu/server.json,\nthen ~/.config/baradwatchu/server.json.\nThe server listens at 127.0.0.1:3000 by default. Set\nBARADWATCHU_SERVER_ADDR to an IP address and port (IPv6: [::1]:3000).\nCtrl-C or SIGTERM drains HTTP connections before shutdown on Linux.\nConfigure the dashboard/OIDC with BARADWATCHU_SERVER_CONFIG (local JSON file).\nPersistent state: BARADWATCHU_SERVER_DATA_DIR (owner-only directory).\n\nLocal provisioning:\n  setup identity generate NAME\n  setup identity export\n  setup admin allow GOOGLE_SUB\n  setup admin revoke GOOGLE_SUB\n  setup client import FILE NAME",
                env!("CARGO_PKG_VERSION")
            );
            Ok(Start::Done)
        }
        _ => Err("invalid arguments; use --help for usage".to_owned()),
    }
}

fn provision(args: &[String]) -> Result<(), String> {
    use baradwatchu_server::{
        config::data_dir,
        storage::{PublicIdentity, Store},
    };
    // Local filesystem ownership is the provisioning boundary, including the first admin.
    let store = Store::open(&data_dir()?)?;
    let output=match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["identity","generate",name] => serde_json::to_value(store.generate(name)?).unwrap(),
        ["identity","export"] => serde_json::to_value(store.identity()?.ok_or("identity not generated")?).unwrap(),
        ["admin","allow",sub] => {store.allow(sub)?;serde_json::json!({"allowed":sub})},
        ["admin","revoke",sub] => {store.revoke(sub)?;serde_json::json!({"revoked":sub})},
        ["client","import",file,name] => {
            let identity:PublicIdentity=serde_json::from_slice(&std::fs::read(file).map_err(|_|"cannot read Client identity")?).map_err(|_|"invalid Client identity JSON")?;
            let fingerprint = baradwatchu_server::storage::fingerprint(&identity.key("client")?);
            serde_json::to_value(store.import(identity,name,&fingerprint)?).unwrap()
        },
        _ => return Err("Usage: setup identity generate NAME | setup identity export | setup admin allow SUB | setup admin revoke SUB | setup client import FILE NAME".into()),
    };
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn dashboard_command_matches_client_options() {
        use super::{parse_start, Start};
        let args = |values: &[&str]| {
            values
                .iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
        };
        assert_eq!(parse_start(&args(&[])).unwrap(), Start::Serve);
        assert_eq!(
            parse_start(&args(&["dashboard"])).unwrap(),
            Start::Dashboard { open_browser: true }
        );
        assert_eq!(
            parse_start(&args(&["dashboard", "--no-browser"])).unwrap(),
            Start::Dashboard {
                open_browser: false
            }
        );
        for bad in [
            &["--no-browser"][..],
            &["dashboard", "--open"],
            &["dashboard", "--no-browser", "x"],
        ] {
            assert!(parse_start(&args(bad)).is_err());
        }
    }
    #[test]
    fn startup_runtime_enables_drivers() {
        super::runtime().unwrap().block_on(async {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        });
    }
}
