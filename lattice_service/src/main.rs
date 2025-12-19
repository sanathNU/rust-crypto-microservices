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


// ============ KEM Operations ============
// 768
fn bench_keygen_768(iterations: u32) -> Vec<u128> {
    let mut timings = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = MlKem768::generate(&mut OsRng);
        timings.push(start.elapsed().as_micros());
    }
    timings
}

fn bench_encaps_768(iterations: u32) -> Vec<u128> {
    // Generating a keypair to use for encapsulation
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    let _ = dk;

    let mut timings = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = ek.encapsulate(&mut OsRng);
        timings.push(start.elapsed().as_micros());
    }
    timings
}

fn bench_decaps_768(iterations: u32) -> Vec<u128> {
    // Generate keypair and encapsulate to get ciphertext
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    let (ct, _ss) = ek.encapsulate(&mut OsRng).unwrap();

    let mut timings = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = dk.decapsulate(&ct);
        timings.push(start.elapsed().as_micros());
    }
    timings
}

fn bench_full_handshake_768(iterations: u32) -> Vec<u128> {
    let mut timings = Vec::with_capacity(iterations as usize);
    
    for _ in 0..iterations {
        let start = Instant::now();
        
        // Full KEM handshake: keygen -> encaps -> decaps
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let (ct, ss_sender) = ek.encapsulate(&mut OsRng).unwrap();
        let ss_receiver = dk.decapsulate(&ct).unwrap();
        
        debug_assert_eq!(ss_sender, ss_receiver);
        
        timings.push(start.elapsed().as_micros());
    }
    timings
}

// 512

fn bench_keygen_512(iterations: u32) -> Vec<u128> {
    let mut timings = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = MlKem512::generate(&mut OsRng);
        timings.push(start.elapsed().as_micros());
    }
    timings
}

fn bench_encaps_512(iterations: u32) -> Vec<u128> {
    let (dk, ek) = MlKem512::generate(&mut OsRng);
    let _ = dk;

    let mut timings = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = ek.encapsulate(&mut OsRng);
        timings.push(start.elapsed().as_micros());
    }
    timings
}

fn bench_decaps_512(iterations: u32) -> Vec<u128> {
    let (dk, ek) = MlKem512::generate(&mut OsRng);
    let (ct, _ss) = ek.encapsulate(&mut OsRng).unwrap();

    let mut timings = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = dk.decapsulate(&ct);
        timings.push(start.elapsed().as_micros());
    }
    timings
}

fn bench_full_handshake_512(iterations: u32) -> Vec<u128> {
    let mut timings = Vec::with_capacity(iterations as usize);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let (dk, ek) = MlKem512::generate(&mut OsRng);
        let (ct, ss_sender) = ek.encapsulate(&mut OsRng).unwrap();
        let ss_receiver = dk.decapsulate(&ct).unwrap();
        
        debug_assert_eq!(ss_sender, ss_receiver);
        
        timings.push(start.elapsed().as_micros());
    }
    timings
}

// 1024


fn bench_keygen_1024(iterations: u32) -> Vec<u128> {
    let mut timings = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = MlKem1024::generate(&mut OsRng);
        timings.push(start.elapsed().as_micros());
    }
    timings
}

fn bench_encaps_1024(iterations: u32) -> Vec<u128> {
    let (dk, ek) = MlKem512::generate(&mut OsRng);
    let _ = dk;

    let mut timings = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = ek.encapsulate(&mut OsRng);
        timings.push(start.elapsed().as_micros());
    }
    timings
}

fn bench_decaps_1024(iterations: u32) -> Vec<u128> {
    let (dk, ek) = MlKem1024::generate(&mut OsRng);
    let (ct, _ss) = ek.encapsulate(&mut OsRng).unwrap();

    let mut timings = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let start = Instant::now();
        let _ = dk.decapsulate(&ct);
        timings.push(start.elapsed().as_micros());
    }
    timings
}

fn bench_full_handshake_1024(iterations: u32) -> Vec<u128> {
    let mut timings = Vec::with_capacity(iterations as usize);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let (dk, ek) = MlKem1024::generate(&mut OsRng);
        let (ct, ss_sender) = ek.encapsulate(&mut OsRng).unwrap();
        let ss_receiver = dk.decapsulate(&ct).unwrap();
        
        debug_assert_eq!(ss_sender, ss_receiver);
        
        timings.push(start.elapsed().as_micros());
    }
    timings
}

// ============ Other operations ============
fn compute_p95(timings: &[u128]) -> f64 {
    if timings.is_empty() {
        return 0.0;
    }
    
    let mut sorted = timings.to_vec();
    sorted.sort_unstable();
    
    // Index for 95th percentile
    let idx = ((sorted.len() as f64) * 0.95) as usize;
    let idx = idx.min(sorted.len() - 1); // don't overflow
    
    sorted[idx] as f64
}

fn compute_stats(timings: &[u128]) -> (f64, f64, f64, f64, f64) {
    let sum: u128 = timings.iter().sum();
    let avg = sum as f64 / timings.len() as f64;
    let min = *timings.iter().min().unwrap_or(&0) as f64;
    let max = *timings.iter().max().unwrap_or(&0) as f64;
    let p95 = compute_p95(timings);
    let throughput = if avg > 0.0 { 1_000_000.0 / avg} else {0.0};

    (avg, min, max, p95, throughput)
}

async fn kem_bench(Json(req): Json<KemBenchRequest>) -> Json<KemBenchResponse> {
    let iterations = req.iterations.min(10000).max(1); // clamp to sane range

    let timings = match (req.param_set.as_str(), req.operation.as_str()) {
        ("ml_kem_768", "keygen") => bench_keygen_768(iterations),
        ("ml_kem_768", "encaps") => bench_encaps_768(iterations),
        ("ml_kem_768", "decaps") => bench_decaps_768(iterations),
        ("ml_kem_768", "full_handshake") => bench_full_handshake_768(iterations),
        ("ml_kem_512", "keygen") => bench_keygen_512(iterations),
        ("ml_kem_512", "encaps") => bench_encaps_512(iterations),
        ("ml_kem_512", "decaps") => bench_decaps_512(iterations),
        ("ml_kem_512", "full_handshake") => bench_full_handshake_512(iterations),
        ("ml_kem_1024", "keygen") => bench_keygen_1024(iterations),
        ("ml_kem_1024", "encaps") => bench_encaps_1024(iterations),
        ("ml_kem_1024", "decaps") => bench_decaps_1024(iterations),
        ("ml_kem_1024", "full_handshake") => bench_full_handshake_1024(iterations),
        _ => vec![0], // unsupported combo
    };

    let (avg_us, min_us, max_us, p95_us, throughput) = compute_stats(&timings);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    Json(KemBenchResponse {
        operation: req.operation,
        param_set: req.param_set,
        iterations,
        avg_us,
        min_us,
        max_us,
        p95_us,
        throughput_ops_sec: throughput,
        timestamp,
    })
}


#[tokio::main]
async fn main() {
    let router = Router::new()
        .route("/health", get(health))
        .route("/kem_bench", post(kem_bench));

    let addr = SocketAddr::from(([127,0,0,1], 8000));
    let tcp = TcpListener::bind(&addr).await.unwrap();
    
    println!("lattice_service listening on {}", addr);
    axum::serve(tcp, router).await.unwrap();
   

}
