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

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey, prepare_verifying_key};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_ff::PrimeField;
use ark_snark::SNARK;
use ark_serialize::CanonicalSerialize;
use rand::rngs::OsRng;

// ============ Health Check ============

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    service: String,
    timestamp: u64,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".into(),
        service: "zk_service".into(),
        timestamp: current_timestamp(),
    })
}

fn current_timestamp() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// ============ Circuits ============

// Circuit 1: Prove knowledge of a,b such that a*b = c(public)
#[derive(Clone)]
struct MultiplyCircuit<F: PrimeField> {
    a: Option<F>,
    b: Option<F>,
    c: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MultiplyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {

        let a_var = FpVar::new_witness(cs.clone() , || {
            self.a.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let b_var = FpVar::new_witness(cs.clone(), || {
            self.b.ok_or(SynthesisError::AssignmentMissing)
        })?;

        //allocating public input
        let c_var = FpVar::new_input(cs.clone(), || {
            self.c.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let ab = &a_var * &b_var;
        ab.enforce_equal(&c_var)?;

        Ok(())
    }
}

// ============ Proving Key Cache ============

struct CircuitKeys {
    multiply_pk: ProvingKey<Bn254>,
    multiply_vk: VerifyingKey<Bn254>,
}

fn setup_circuits() -> CircuitKeys {
    println!("Running trusted setup for circuits...");

    let dummy_multiply = MultiplyCircuit::<Fr> { a: None, b: None, c: None };
    let (multiply_pk, multiply_vk) = Groth16::<Bn254>::circuit_specific_setup(
        dummy_multiply, &mut OsRng
    ).expect("Setup failed for multiply circuit");

    println!("Trusted setup complete.");

    CircuitKeys { multiply_pk, multiply_vk }
}

// ============ Error Types ============

enum AppError {
    InvalidCircuit(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::InvalidCircuit(circuit_id) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid circuit_id: {}", circuit_id)
            ),
        };
        (status, message).into_response()
    }
}

// ============ Benchmark Types ============

#[derive(Deserialize)]
struct ZkBenchRequest {
    circuit_id: String,
    iterations: u32,
}

#[derive(Serialize)]
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


#[derive(Serialize)]
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

struct Stats {
    avg_ms: f64,
    min_ms: f64,
    max_ms: f64,
    p95_ms: f64,
    throughput: f64,
}

fn compute_stats(timings_us: &[u128]) -> Stats {
    if timings_us.is_empty() {
        return Stats { avg_ms: 0.0, min_ms: 0.0, max_ms: 0.0, p95_ms: 0.0, throughput: 0.0 };
    }

    let sum: u128 = timings_us.iter().sum();
    let avg_us = sum as f64 / timings_us.len() as f64;
    let min_us = *timings_us.iter().min().unwrap() as f64;
    let max_us = *timings_us.iter().max().unwrap() as f64;
    let p95_us = compute_percentile(timings_us, 0.95);

    // Convert to milliseconds 
    let avg_ms = avg_us / 1000.0;
    let throughput = if avg_ms > 0.0 { 1000.0 / avg_ms } else { 0.0 };

    Stats {
        avg_ms,
        min_ms: min_us / 1000.0,
        max_ms: max_us / 1000.0,
        p95_ms: p95_us / 1000.0,
        throughput,
    }
}


fn compute_percentile(timings: &[u128], percentile: f64) -> f64 {
    let mut sorted = timings.to_vec();
    sorted.sort_unstable();
    let idx = ((sorted.len() as f64) * percentile) as usize;
    
    sorted[idx.min(sorted.len() - 1)] as f64
}


fn bench_prove_multiply(pk: &ProvingKey<Bn254>, iterations: u32) -> (Vec<u128>, usize) {
    let mut timings = Vec::with_capacity(iterations as usize);
    let mut proof_size = 0;

    for i in 0..iterations {
        
        let a = Fr::from((i+3) as u64);
        let b = Fr::from((i+7) as u64);
        let c = a*b;

        let circuit = MultiplyCircuit { a: Some(a), b: Some(b), c: Some(c) };

        let start = Instant::now();
        let proof = Groth16::<Bn254>::prove(pk, circuit, &mut OsRng)
            .expect("Proving failed");
        timings.push(start.elapsed().as_micros());

        if proof_size == 0 {
            proof_size = proof.serialized_size(ark_serialize::Compress::Yes);
        }
    }
    (timings, proof_size)
}

fn bench_verify_multiply(pk: &ProvingKey<Bn254>, vk: &VerifyingKey<Bn254>, iterations: u32) -> Vec<u128> {
    // Generate one valid proof to verify repeatedly
    let a = Fr::from(3u64);
    let b = Fr::from(7u64);
    let c = a * b;

    let circuit = MultiplyCircuit { a: Some(a), b: Some(b), c: Some(c) };
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut OsRng).expect("Proving failed");
    let pvk = prepare_verifying_key(vk);

    let public_inputs = vec![c];

    (0..iterations)
        .map(|_| {
            let start = Instant::now();
            let valid = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
                .expect("Verification failed");
            assert!(valid);
            start.elapsed().as_micros()
        })
        .collect()
}

async fn zk_prove_bench(
    axum::extract::State(keys): axum::extract::State<std::sync::Arc<CircuitKeys>>,
    Json(req): Json<ZkBenchRequest>,
) -> Result<Json<ZkProveBenchResponse>, AppError> {
    let iterations = req.iterations.clamp(1, 1000); // ZK is slower, lower cap

    let (timings, proof_size) = match req.circuit_id.as_str() {
        "multiply" => bench_prove_multiply(&keys.multiply_pk, iterations),
        _ => return Err(AppError::InvalidCircuit(req.circuit_id)),
    };

    let stats = compute_stats(&timings);

    Ok(Json(ZkProveBenchResponse {
        circuit_id: req.circuit_id,
        iterations,
        avg_prove_ms: stats.avg_ms,
        min_prove_ms: stats.min_ms,
        max_prove_ms: stats.max_ms,
        p95_prove_ms: stats.p95_ms,
        avg_proof_size_bytes: proof_size,
        throughput_proofs_sec: stats.throughput,
        timestamp: current_timestamp(),
    }))
}

async fn zk_verify_bench(
    axum::extract::State(keys): axum::extract::State<std::sync::Arc<CircuitKeys>>,
    Json(req): Json<ZkBenchRequest>,
) -> Result<Json<ZkVerifyBenchResponse>, AppError> {
    let iterations = req.iterations.clamp(1, 5000);

    let timings = match req.circuit_id.as_str() {
        "multiply" => bench_verify_multiply(&keys.multiply_pk, &keys.multiply_vk, iterations),
        _ => return Err(AppError::InvalidCircuit(req.circuit_id)),
    };

    let stats = compute_stats(&timings);

    Ok(Json(ZkVerifyBenchResponse {
        circuit_id: req.circuit_id,
        iterations,
        avg_verify_ms: stats.avg_ms,
        min_verify_ms: stats.min_ms,
        max_verify_ms: stats.max_ms,
        p95_verify_ms: stats.p95_ms,
        throughput_verifies_sec: stats.throughput,
        timestamp: current_timestamp(),
    }))
}


#[tokio::main]
async fn main() {

    let keys = std::sync::Arc::new(setup_circuits());

    let router = Router::new()
        .route("/health", get(health))
        .route("/zk_prove_bench", post(zk_prove_bench))
        .route("/zk_verify_bench", post(zk_verify_bench))
        .with_state(keys);

    

    let addr = SocketAddr::from(([127, 0, 0, 1], 8001));
    println!("zk_service listening on {}", addr);

    let tcp = TcpListener::bind(&addr).await.unwrap();
    axum::serve(tcp, router).await.unwrap();
}