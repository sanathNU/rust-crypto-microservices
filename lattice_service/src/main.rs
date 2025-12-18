use axum::{Router, routing::get, Json};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use serde::Serialize;

async fn hello_world() -> &'static str {
    "Namaste World!"
}

async fn return_some_json() -> Json<Value> {
    let json = json!({"Hey":"yaall"});
    
    Json(json)
}

#[tokio::main]
async fn main() {
    let router = Router::new().route("/", get(hello_world));

    let addr = SocketAddr::from(([127,0,0,1], 8000));
    let tcp = TcpListener::bind(&addr).await.unwrap();

    axum::serve(tcp, router).await.unwrap();
}
