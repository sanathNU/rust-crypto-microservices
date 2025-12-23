use axum::{
    debug_handler,
    Router,
    routing::{get, post},
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use tokio::net::TcpListener;
use serde::{Deserialize, Serialize};
use ml_kem::{*, kem::{Encapsulate, Decapsulate}};
use rand::rngs::OsRng;

// === Health Check service ==

#[derive(serde::Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    timestamp: u64,
}

#[debug_handler]
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        service: "lattice_service".to_string(),
        timestamp: current_timestamp(),
    })
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ============ Error Handling ============

#[derive(Debug)]
enum AppError {
    InvalidParamSet(String),
    InvalidOperation(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::InvalidParamSet(s) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid param_set '{}'. Valid options: ml_kem_512, ml_kem_768, ml_kem_1024", s)
            ),
            AppError::InvalidOperation(s) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid operation '{}'. Valid options: keygen, encaps, decaps, full_handshake", s)
            ),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

// ============ KEM Benchmark Types ============

#[derive(Deserialize)]
struct KemBenchRequest {
    param_set: String, 
    iterations: u32,
    operation: String,
}

#[derive(Serialize)]
struct KemBenchResponse {
    operation: String,
    param_set: String,
    iterations: u32,
    avg_us: f64,
    min_us: f64,
    max_us: f64,
    p95_us: f64,
    throughput_ops_sec: f64,
    timestamp: u64,
}

// ============ Generic KEM Constructs ============

trait BenchmarkableKem: KemCore
where
    <Self as KemCore>::DecapsulationKey: Decapsulate<Ciphertext<Self>, SharedKey<Self>>,
    <Self as KemCore>::EncapsulationKey: Encapsulate<Ciphertext<Self>, SharedKey<Self>>,
{
}

impl<T> BenchmarkableKem for T
where
    T: KemCore,
    <T as KemCore>::DecapsulationKey: Decapsulate<Ciphertext<T>, SharedKey<T>>,
    <T as KemCore>::EncapsulationKey: Encapsulate<Ciphertext<T>, SharedKey<T>>,
{
}

// ============ KEM Operations ============

fn bench_keygen<K: KemCore>(iterations: u32) -> Vec<u128> {
    (0..iterations)
        .map( |_| {
            let start = Instant::now();
            let _ = K::generate(&mut OsRng);
            start.elapsed().as_micros()
        })
        .collect()
}

fn bench_encaps<K>(iterations: u32) -> Vec<u128>
where
    K: KemCore,
    K::EncapsulationKey: Encapsulate<Ciphertext<K>, SharedKey<K>>,
{
    let (_dk, ek) = K::generate(&mut OsRng);

    (0..iterations)
        .map(|_| {
            let start = Instant::now();
            let _ = ek.encapsulate(&mut OsRng);
            start.elapsed().as_micros()
        })
        .collect()
}

fn bench_decaps<K>(iterations: u32) -> Vec<u128>
where
    K: KemCore,
    K::EncapsulationKey: Encapsulate<Ciphertext<K>, SharedKey<K>>,
    K::DecapsulationKey: Decapsulate<Ciphertext<K>, SharedKey<K>>,
{
    let (dk, ek) = K::generate(&mut OsRng);
    let (ct, _ss) = ek.encapsulate(&mut OsRng).unwrap();

    (0..iterations)
        .map(|_| {
            let start = Instant::now();
            let _ = dk.decapsulate(&ct);
            start.elapsed().as_micros()
        })
        .collect()
}

fn bench_full_handshake<K>(iterations: u32) -> Vec<u128>
where
    K: KemCore,
    K::EncapsulationKey: Encapsulate<Ciphertext<K>, SharedKey<K>>,
    K::DecapsulationKey: Decapsulate<Ciphertext<K>, SharedKey<K>>,
{
    (0..iterations)
        .map(|_| {
            let start = Instant::now();
            let (dk, ek) = K::generate(&mut OsRng);
            let (ct, ss_sender) = ek.encapsulate(&mut OsRng).unwrap();
            let ss_receiver = dk.decapsulate(&ct).unwrap();
            debug_assert_eq!(ss_sender, ss_receiver);
            start.elapsed().as_micros()
        })
        .collect()
}

// Dispatch to the right generic function based on param_set
fn run_benchmark(param_set: &str, operation: &str, iterations: u32) -> Result<Vec<u128>, AppError> {
    match param_set {
        "ml_kem_512" => run_operation::<MlKem512>(operation, iterations),
        "ml_kem_768" => run_operation::<MlKem768>(operation, iterations),
        "ml_kem_1024" => run_operation::<MlKem1024>(operation, iterations),
        _ => Err(AppError::InvalidParamSet(param_set.to_string())),
    }
}

fn run_operation<K>(operation: &str, iterations: u32) -> Result<Vec<u128>, AppError>
where
    K: KemCore,
    K::EncapsulationKey: Encapsulate<Ciphertext<K>, SharedKey<K>>,
    K::DecapsulationKey: Decapsulate<Ciphertext<K>, SharedKey<K>>,
{
    match operation {
        "keygen" => Ok(bench_keygen::<K>(iterations)),
        "encaps" => Ok(bench_encaps::<K>(iterations)),
        "decaps" => Ok(bench_decaps::<K>(iterations)),
        "full_handshake" => Ok(bench_full_handshake::<K>(iterations)),
        _ => Err(AppError::InvalidOperation(operation.to_string())),
    }
}



// ============ Other operations ============
struct Stats {
    avg: f64,
    min: f64,
    max: f64,
    p95: f64,
    throughput: f64,
}

fn compute_stats(timings: &[u128]) -> Stats {
    if timings.is_empty() {
        return Stats { avg: 0.0, min: 0.0, max: 0.0, p95: 0.0, throughput: 0.0 };
    }

    let sum: u128 = timings.iter().sum();
    let avg = sum as f64 / timings.len() as f64;
    let min = *timings.iter().min().unwrap() as f64;
    let max = *timings.iter().max().unwrap() as f64;
    let p95 = compute_percentile(timings, 0.95);
    let throughput = if avg > 0.0 { 1_000_000.0 / avg } else { 0.0 };

    Stats { avg, min, max, p95, throughput }
}

fn compute_percentile(timings: &[u128], percentile: f64) -> f64 {
    let mut sorted = timings.to_vec();
    sorted.sort_unstable();
    let idx = ((sorted.len() as f64) * percentile) as usize;
    sorted[idx.min(sorted.len() - 1)] as f64
}

async fn kem_bench(
    Json(req): Json<KemBenchRequest>,
) -> Result<Json<KemBenchResponse>, AppError> {
    let iterations = req.iterations.clamp(1, 10000);

    let timings = run_benchmark(&req.param_set, &req.operation, iterations)?;
    let stats = compute_stats(&timings);

    Ok(Json(KemBenchResponse {
        operation: req.operation,
        param_set: req.param_set,
        iterations,
        avg_us: stats.avg,
        min_us: stats.min,
        max_us: stats.max,
        p95_us: stats.p95,
        throughput_ops_sec: stats.throughput,
        timestamp: current_timestamp(),
    }))
}



#[tokio::main]
async fn main() {
    let router = Router::new()
        .route("/health", get(health))
        .route("/kem_bench", post(kem_bench));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    let tcp = TcpListener::bind(&addr).await.unwrap();
    
    println!("lattice_service listening on {}", addr);
    axum::serve(tcp, router).await.unwrap();
   

}
