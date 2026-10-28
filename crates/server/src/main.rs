use axum::{routing::get, Json, Router};
use std::{env, net::SocketAddr};

#[tokio::main]
async fn main() {
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
