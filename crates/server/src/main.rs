use axum::{routing::get, Json, Router};
use std::{env, net::SocketAddr};

fn main() {
    if let Err(error) = handle_cli() {
        eprintln!("{error}");
        std::process::exit(2);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .build()
        .expect("failed to create Tokio runtime");
    runtime.block_on(run_server());
}

async fn run_server() {
    let address =
        env::var("BARADWATCHU_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_owned());
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .expect("failed to bind server address");
    let address: SocketAddr = listener.local_addr().expect("failed to read bound address");
    println!("BaradWatchU server listening on http://{address}");

    let app = Router::new().route("/health", get(health));
    axum::serve(listener, app).await.expect("server failed");
}

fn handle_cli() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => Ok(()),
        [flag] if flag == "--version" || flag == "-V" => {
            println!("BaradWatchU Server {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        [flag] if flag == "--help" || flag == "-h" => {
            println!(
                "BaradWatchU Server {}\n\nUsage: baradwatchu-server [OPTIONS]\n\nOptions:\n  -h, --help       Show this help and exit\n  -V, --version    Show product version and exit\n\nThe development server listens at 127.0.0.1:3000 by default. Set\nBARADWATCHU_SERVER_ADDR to choose another address. The Angular dashboard\nis built separately and is not served by this bootstrap.",
                env!("CARGO_PKG_VERSION")
            );
            std::process::exit(0);
        }
        _ => Err("invalid arguments; use --help for usage".to_owned()),
    }
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "baradwatchu-server",
    })
}

#[derive(serde::Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}
