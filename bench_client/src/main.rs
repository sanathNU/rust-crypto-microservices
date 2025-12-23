use clap::{Parser, Subcommand};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use chrono::Utc;

#[derive(Parser)]
#[command(name = "bench_client")]
#[command(about = "Benchmark client for lattice and ZK services")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, default_value="json", global = true)]
    output: String,

    #[arg(long, global = true)]
    file: Option<String>,

    #[arg(long, default_value = "default", global = true)]
    label: String,
}


#[derive(Subcommand)]
enum Commands {
    /// Benchmark KEM operations
    Kem {
        /// Service URL
        #[arg(long, default_value = "http://localhost:8000")]
        url: String,

        /// Parameter set: ml_kem_512, ml_kem_768, ml_kem_1024
        #[arg(long, default_value = "ml_kem_768")]
        param_set: String,

        /// Operation: keygen, encaps, decaps, full_handshake
        #[arg(long, default_value = "full_handshake")]
        operation: String,

        /// Iterations per request
        #[arg(long, default_value = "100")]
        iterations: u32,

        /// Number of requests to make (for client-side concurrency testing)
        #[arg(long, default_value = "1")]
        requests: u32,

        /// Concurrent requests
        #[arg(long, default_value = "1")]
        concurrency: u32,
    },
    /// Benchmark ZK proving
    ZkProve {
        /// Service URL
        #[arg(long, default_value = "http://localhost:8001")]
        url: String,

        /// Circuit ID: multiply, cube_root
        #[arg(long, default_value = "multiply")]
        circuit_id: String,

        /// Iterations per request
        #[arg(long, default_value = "10")]
        iterations: u32,

        /// Number of requests
        #[arg(long, default_value = "1")]
        requests: u32,

        /// Concurrent requests
        #[arg(long, default_value = "1")]
        concurrency: u32,
    },
    /// Benchmark ZK verification
    ZkVerify {
        /// Service URL
        #[arg(long, default_value = "http://localhost:8001")]
        url: String,

        /// Circuit ID: multiply, cube_root
        #[arg(long, default_value = "multiply")]
        circuit_id: String,

        /// Iterations per request
        #[arg(long, default_value = "100")]
        iterations: u32,

        /// Number of requests
        #[arg(long, default_value = "1")]
        requests: u32,

        /// Concurrent requests
        #[arg(long, default_value = "1")]
        concurrency: u32,
    },
    /// Run full benchmark suite
    Suite {
        /// Lattice service URL
        #[arg(long, default_value = "http://localhost:8000")]
        lattice_url: String,

        /// ZK service URL
        #[arg(long, default_value = "http://localhost:8001")]
        zk_url: String,

        /// Iterations for KEM benchmarks
        #[arg(long, default_value = "100")]
        kem_iterations: u32,

        /// Iterations for ZK benchmarks
        #[arg(long, default_value = "10")]
        zk_iterations: u32,
    },
}


#[derive(Serialize)]
struct KemBenchRequest {
    param_set: String,
    iterations: u32,
    operation: String,
}

#[derive(Deserialize, Debug)]
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

#[derive(Serialize)]
struct ZkBenchRequest {
    circuit_id: String,
    iterations: u32,
}

#[derive(Deserialize, Debug)]
struct ZkProveBenchResponse {
    circuit_id: String,
    iterations: u32,
    avg_prove_ms: f64,
    min_prove_ms: f64,
    max_prove_ms: f64,
    p95_prove_ms: f64,
    avg_proof_size_bytes: usize,
    throughput_proofs_sec: f64,
    timestamp: u64,
}

#[derive(Deserialize, Debug)]
struct ZkVerifyBenchResponse {
    circuit_id: String,
    iterations: u32,
    avg_verify_ms: f64,
    min_verify_ms: f64,
    max_verify_ms: f64,
    p95_verify_ms: f64,
    throughput_verifies_sec: f64,
    timestamp: u64,
}

// ============ Unified Result Type ============

#[derive(Serialize)]
struct BenchmarkResult {
    timestamp: String,
    label: String,
    service: String,
    operation: String,
    param_set: String,
    iterations: u32,
    requests: u32,
    concurrency: u32,
    avg_latency_ms: f64,
    min_latency_ms: f64,
    max_latency_ms: f64,
    p95_latency_ms: f64,
    throughput_ops_sec: f64,
    client_total_time_ms: f64,
    client_avg_request_ms: f64,
    error_count: u32,
}

// =====

async fn run_kem_benchmark( 
    client: &Client, url: &str, param_set: &str, operation: &str,
    iterations: u32, requests: u32, concurrency: u32,
    label: &str ) 
    -> BenchmarkResult {

    let endpoint = format!("{}/kem_bench", url);
    let req_body = KemBenchRequest {
        param_set: param_set.to_string(),
        iterations,
        operation: operation.to_string(),
    };

    let start = Instant::now();
    let mut results: Vec<KemBenchResponse> = Vec::new();
    let mut errors = 0u32;

    // Run requests with concurrency
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency as usize));
    let mut handles = Vec::new();

    for _ in 0..requests {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let endpoint = endpoint.clone();
        let body = serde_json::to_string(&req_body).unwrap();

        handles.push(tokio::spawn(async move {
            let res = client
                .post(&endpoint)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await;
            drop(permit);
            res
        }));
    }

    for handle in handles {
        match handle.await {
            Ok(Ok(response)) => {
                if let Ok(data) = response.json::<KemBenchResponse>().await {
                    results.push(data);
                } else {
                    errors += 1;
                }
            }
            _ => errors += 1,
        }
    }

    let total_time = start.elapsed().as_millis() as f64;

    // Aggregate results
    let (avg_lat, min_lat, max_lat, p95_lat, throughput) = if !results.is_empty() {
        let avg = results.iter().map(|r| r.avg_us).sum::<f64>() / results.len() as f64;
        let min = results.iter().map(|r| r.min_us).fold(f64::MAX, f64::min);
        let max = results.iter().map(|r| r.max_us).fold(0.0, f64::max);
        let p95 = results.iter().map(|r| r.p95_us).sum::<f64>() / results.len() as f64;
        let tp = results.iter().map(|r| r.throughput_ops_sec).sum::<f64>() / results.len() as f64;
        (avg / 1000.0, min / 1000.0, max / 1000.0, p95 / 1000.0, tp)
    } else {
        (0.0, 0.0, 0.0, 0.0, 0.0)
    };

    BenchmarkResult {
        timestamp: Utc::now().to_rfc3339(),
        label: label.to_string(),
        service: "lattice_service".to_string(),
        operation: operation.to_string(),
        param_set: param_set.to_string(),
        iterations,
        requests,
        concurrency,
        avg_latency_ms: avg_lat,
        min_latency_ms: min_lat,
        max_latency_ms: max_lat,
        p95_latency_ms: p95_lat,
        throughput_ops_sec: throughput,
        client_total_time_ms: total_time,
        client_avg_request_ms: total_time / requests as f64,
        error_count: errors,
    }
}

async fn run_zk_prove_benchmark(
    client: &Client,
    url: &str,
    circuit_id: &str,
    iterations: u32,
    requests: u32,
    concurrency: u32,
    label: &str,
) -> BenchmarkResult {
    let endpoint = format!("{}/zk_prove_bench", url);
    let req_body = ZkBenchRequest {
        circuit_id: circuit_id.to_string(),
        iterations,
    };

    let start = Instant::now();
    let mut results: Vec<ZkProveBenchResponse> = Vec::new();
    let mut errors = 0u32;

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency as usize));
    let mut handles = Vec::new();

    for _ in 0..requests {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let endpoint = endpoint.clone();
        let body = serde_json::to_string(&req_body).unwrap();

        handles.push(tokio::spawn(async move {
            let res = client
                .post(&endpoint)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await;
            drop(permit);
            res
        }));
    }

    for handle in handles {
        match handle.await {
            Ok(Ok(response)) => {
                if let Ok(data) = response.json::<ZkProveBenchResponse>().await {
                    results.push(data);
                } else {
                    errors += 1;
                }
            }
            _ => errors += 1,
        }
    }

    let total_time = start.elapsed().as_millis() as f64;

    let (avg_lat, min_lat, max_lat, p95_lat, throughput) = if !results.is_empty() {
        let avg = results.iter().map(|r| r.avg_prove_ms).sum::<f64>() / results.len() as f64;
        let min = results.iter().map(|r| r.min_prove_ms).fold(f64::MAX, f64::min);
        let max = results.iter().map(|r| r.max_prove_ms).fold(0.0, f64::max);
        let p95 = results.iter().map(|r| r.p95_prove_ms).sum::<f64>() / results.len() as f64;
        let tp = results.iter().map(|r| r.throughput_proofs_sec).sum::<f64>() / results.len() as f64;
        (avg, min, max, p95, tp)
    } else {
        (0.0, 0.0, 0.0, 0.0, 0.0)
    };

    BenchmarkResult {
        timestamp: Utc::now().to_rfc3339(),
        label: label.to_string(),
        service: "zk_service".to_string(),
        operation: "prove".to_string(),
        param_set: circuit_id.to_string(),
        iterations,
        requests,
        concurrency,
        avg_latency_ms: avg_lat,
        min_latency_ms: min_lat,
        max_latency_ms: max_lat,
        p95_latency_ms: p95_lat,
        throughput_ops_sec: throughput,
        client_total_time_ms: total_time,
        client_avg_request_ms: total_time / requests as f64,
        error_count: errors,
    }
}

async fn run_zk_verify_benchmark(
    client: &Client,
    url: &str,
    circuit_id: &str,
    iterations: u32,
    requests: u32,
    concurrency: u32,
    label: &str,
) -> BenchmarkResult {
    let endpoint = format!("{}/zk_verify_bench", url);
    let req_body = ZkBenchRequest {
        circuit_id: circuit_id.to_string(),
        iterations,
    };

    let start = Instant::now();
    let mut results: Vec<ZkVerifyBenchResponse> = Vec::new();
    let mut errors = 0u32;

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency as usize));
    let mut handles = Vec::new();

    for _ in 0..requests {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let endpoint = endpoint.clone();
        let body = serde_json::to_string(&req_body).unwrap();

        handles.push(tokio::spawn(async move {
            let res = client
                .post(&endpoint)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await;
            drop(permit);
            res
        }));
    }

    for handle in handles {
        match handle.await {
            Ok(Ok(response)) => {
                if let Ok(data) = response.json::<ZkVerifyBenchResponse>().await {
                    results.push(data);
                } else {
                    errors += 1;
                }
            }
            _ => errors += 1,
        }
    }

    let total_time = start.elapsed().as_millis() as f64;

    let (avg_lat, min_lat, max_lat, p95_lat, throughput) = if !results.is_empty() {
        let avg = results.iter().map(|r| r.avg_verify_ms).sum::<f64>() / results.len() as f64;
        let min = results.iter().map(|r| r.min_verify_ms).fold(f64::MAX, f64::min);
        let max = results.iter().map(|r| r.max_verify_ms).fold(0.0, f64::max);
        let p95 = results.iter().map(|r| r.p95_verify_ms).sum::<f64>() / results.len() as f64;
        let tp = results.iter().map(|r| r.throughput_verifies_sec).sum::<f64>() / results.len() as f64;
        (avg, min, max, p95, tp)
    } else {
        (0.0, 0.0, 0.0, 0.0, 0.0)
    };

    BenchmarkResult {
        timestamp: Utc::now().to_rfc3339(),
        label: label.to_string(),
        service: "zk_service".to_string(),
        operation: "verify".to_string(),
        param_set: circuit_id.to_string(),
        iterations,
        requests,
        concurrency,
        avg_latency_ms: avg_lat,
        min_latency_ms: min_lat,
        max_latency_ms: max_lat,
        p95_latency_ms: p95_lat,
        throughput_ops_sec: throughput,
        client_total_time_ms: total_time,
        client_avg_request_ms: total_time / requests as f64,
        error_count: errors,
    }
}

// ============ Output ============

fn output_results(results: &[BenchmarkResult], format: &str, file: Option<&str>) {
    let output = match format {
        "csv" => {
            let mut wtr = csv::Writer::from_writer(vec![]);
            for r in results {
                wtr.serialize(r).unwrap();
            }
            String::from_utf8(wtr.into_inner().unwrap()).unwrap()
        }
        _ => serde_json::to_string_pretty(results).unwrap(),
    };

    match file {
        Some(path) => std::fs::write(path, &output).expect("Failed to write file"),
        None => println!("{}", output),
    }
}


#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = Client::new();
    let mut results = Vec::new();

    match cli.command {
        Commands::Kem {url, param_set, operation, iterations, requests, concurrency } => {
            println!("Running KEM benchmark: {} {} x{}", param_set, operation, iterations);
            let result = run_kem_benchmark(
                &client, &url, &param_set, &operation, iterations, requests, concurrency, &cli.label
            ).await;
            results.push(result);
        }
        Commands::ZkProve { url, circuit_id, iterations, requests, concurrency } => {
            println!("Running ZK prove benchmark: {} x{}", circuit_id, iterations);
            let result = run_zk_prove_benchmark(
                &client, &url, &circuit_id, iterations, requests, concurrency, &cli.label
            ).await;
            results.push(result);
        }
        Commands::ZkVerify { url, circuit_id, iterations, requests, concurrency } => {
            println!("Running ZK verify benchmark: {} x{}", circuit_id, iterations);
            let result = run_zk_verify_benchmark(
                &client, &url, &circuit_id, iterations, requests, concurrency, &cli.label
            ).await;
            results.push(result);
        }
        Commands::Suite { lattice_url, zk_url, kem_iterations, zk_iterations } => {
            println!("Running full benchmark suite...\n");
            
            for param_set in ["ml_kem_512", "ml_kem_767", "ml_kem_1024"] {
                for operation in ["keygen", "encaps", "decaps", "full_handshake"] {
                    println!(" KEM: {} {}", param_set, operation);
                    let result = run_kem_benchmark(
                        &client, &lattice_url, param_set, operation, kem_iterations, 1, 1, &cli.label
                    ).await;
                    results.push(result);
                }
            }

            for circuit_id in ["multiply", "cube_root"] {
                println!(" ZK prove: {}", circuit_id);
                let result = run_zk_prove_benchmark(
                    &client, &zk_url, circuit_id, zk_iterations, 1, 1, &cli.label
                ).await;
                results.push(result);
        

                println!("  ZK verify: {}", circuit_id);
                let result = run_zk_verify_benchmark(
                    &client, &zk_url, circuit_id, zk_iterations * 10, 1, 1, &cli.label
                ).await;
                results.push(result);
            }

        println!("\nSuite complete.");
        }
    }
    output_results(&results, &cli.output, cli.file.as_deref());
}
