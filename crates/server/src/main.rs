use baradwatchu_server::config::Config;
use std::{io, process::ExitCode};

fn main() -> ExitCode {
    match handle_cli() {
        Ok(false) => return ExitCode::SUCCESS,
        Ok(true) => {}
        Err(error) => {
            eprintln!("Error: {error}");
            return ExitCode::from(2);
        }
    }
    match start() {
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

fn start() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    runtime()?.block_on(run_server(config))?;
    Ok(())
}

async fn run_server(config: Config) -> io::Result<()> {
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
        return Err(io::Error::other("dashboard assets missing; rebuild/reinstall the Server or configure webDir"));
    }
    println!("Dashboard: {} (mode {:?})", settings.origin(), settings.auth_mode);
    let store = baradwatchu_server::storage::Store::open(
        &baradwatchu_server::config::data_dir().map_err(io::Error::other)?,
    ).map_err(io::Error::other)?;
    let routes = baradwatchu_server::http::application(
        baradwatchu_server::http::App::new(store, settings).map_err(io::Error::other)?,
    );
    axum::serve(listener, routes)
        .with_graceful_shutdown(shutdown)
        .await
}

/// Return whether normal startup was requested; informational flags start no runtime.
fn handle_cli() -> Result<bool, String> {
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
        return Ok(false);
    }
    match args.as_slice() {
        [] => Ok(true),
        [command] if command == "dashboard" => Ok(true),
        [flag] if flag == "--version" || flag == "-V" => {
            println!("BaradWatchU Server {}", env!("CARGO_PKG_VERSION"));
            Ok(false)
        }
        [flag] if flag == "--help" || flag == "-h" => {
            println!(
                "BaradWatchU Server {}\n\nUsage: baradwatchu-server [dashboard | OPTIONS]\n\nOptions:\n  -h, --help       Show this help and exit\n  -V, --version    Show product version and exit\n\nStart without arguments or with dashboard; keep the process running.\nWithout server.json, the full dashboard uses LOCAL authentication on loopback.\nConfiguration: BARADWATCHU_SERVER_CONFIG, /etc/baradwatchu/server.json,\nthen ~/.config/baradwatchu/server.json.\nThe server listens at 127.0.0.1:3000 by default. Set\nBARADWATCHU_SERVER_ADDR to an IP address and port (IPv6: [::1]:3000).\nCtrl-C or SIGTERM drains HTTP connections before shutdown on Linux.\nConfigure the dashboard/OIDC with BARADWATCHU_SERVER_CONFIG (local JSON file).\nPersistent state: BARADWATCHU_SERVER_DATA_DIR (owner-only directory).\n\nLocal provisioning:\n  setup identity generate NAME\n  setup identity export\n  setup admin allow GOOGLE_SUB\n  setup admin revoke GOOGLE_SUB\n  setup client import FILE IP:PORT NAME SHA256:FINGERPRINT",
                env!("CARGO_PKG_VERSION")
            );
            Ok(false)
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
        ["client","import",file,endpoint,name,fingerprint] => {
            let identity:PublicIdentity=serde_json::from_slice(&std::fs::read(file).map_err(|_|"cannot read Client identity")?).map_err(|_|"invalid Client identity JSON")?;
            serde_json::to_value(store.import(identity,name,endpoint,fingerprint)?).unwrap()
        },
        _ => return Err("Usage: setup identity generate NAME | setup identity export | setup admin allow SUB | setup admin revoke SUB | setup client import FILE IP:PORT NAME FINGERPRINT".into()),
    };
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn startup_runtime_enables_drivers() {
        super::runtime().unwrap().block_on(async {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        });
    }
}
