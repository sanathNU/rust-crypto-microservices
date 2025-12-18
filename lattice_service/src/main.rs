use axum::{debug_handler, Router, routing::get, Json};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

// === Health Check service ==

#[derive(serde::Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    timestamp: u64,
}

#[debug_handler]
async fn health() -> Json<HealthResponse> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Json(HealthResponse {
        status: "healthy".to_string(),
        service: "lattice_service".to_string(),
        timestamp,
    })
}

#[tokio::main]
async fn main() {
    let router = Router::new()
        .route("/health", get(health));

    let addr = SocketAddr::from(([127,0,0,1], 8000));
    let tcp = TcpListener::bind(&addr).await.unwrap();
     println!("lattice_service listening on {}", addr};
    axum::serve(tcp, router).await.unwrap();
   

}
