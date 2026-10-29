use baradwatchu_server::{config::Config, http::router};
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
    axum::serve(listener, router())
        .with_graceful_shutdown(shutdown)
        .await
}

/// Return whether normal startup was requested; informational flags start no runtime.
fn handle_cli() -> Result<bool, String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => Ok(true),
        [flag] if flag == "--version" || flag == "-V" => {
            println!("BaradWatchU Server {}", env!("CARGO_PKG_VERSION"));
            Ok(false)
        }
        [flag] if flag == "--help" || flag == "-h" => {
            println!(
                "BaradWatchU Server {}\n\nUsage: baradwatchu-server [OPTIONS]\n\nOptions:\n  -h, --help       Show this help and exit\n  -V, --version    Show product version and exit\n\nThe development server listens at 127.0.0.1:3000 by default. Set\nBARADWATCHU_SERVER_ADDR to an IP address and port (IPv6: [::1]:3000).\nCtrl-C or SIGTERM drains HTTP connections before shutdown on Linux.\nThe Angular dashboard is built and launched separately.",
                env!("CARGO_PKG_VERSION")
            );
            Ok(false)
        }
        _ => Err("invalid arguments; use --help for usage".to_owned()),
    }
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
