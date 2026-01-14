# rust-crypto-microservices

A template for building and deploying cryptographic operations as HTTP microservices in Rust.

Uses post-quantum key encapsulation (ML-KEM) and zero-knowledge proofs (Groth16) as example workloads, but the patterns here apply to any compute-intensive Rust service.

## What's Here

```
├── lattice_service/     # ML-KEM operations as HTTP endpoints
├── zk_service/          # Groth16 proving/verification endpoints  
├── bench_client/        # CLI for load testing and benchmarking
├── common/              # Shared types and utilities
├── docker/              # Multi-stage Dockerfiles
└── k8s/                 # Kubernetes deployment manifests
```

## Quick Start

### Local Build (Native)
```bash
# Build all services
cargo build --release

# Terminal 1: Start lattice service
./target/release/lattice_service

# Terminal 2: Start ZK service
./target/release/zk_service

# Terminal 3: Run benchmarks
./target/release/bench_client suite \
  --lattice-url http://localhost:8000 \
  --zk-url http://localhost:8001
```

### Docker Compose
```bash
docker-compose up -d lattice-service zk-service
curl http://localhost:8000/health
curl http://localhost:8001/health

# Run benchmarks
docker-compose run --rm bench-client suite \
  --lattice-url http://lattice-service:8000 \
  --zk-url http://zk-service:8001
```
## Architecture
![](Architecture.png)

Each service:
- Runs the crypto operation N times
- Measures timing internally (not HTTP overhead)
- Returns aggregated stats (avg, min, max, p95, throughput)

The bench client drives load and collects results to CSV/JSON.

## API Shape

Services expose a consistent pattern:

```
GET /health          → { "status": "ok" }
POST /<operation>     → { params } → { results + timing }
```

Example request:
```json
POST /kem_bench
{
  "param_set": "ml_kem_768",
  "iterations": 100,
  "operation": "full_handshake"
}
```

Example response:
```json
{
  "operation": "full_handshake",
  "iterations": 100,
  "avg_us": 45.2,
  "p95_us": 52.1,
  "throughput_ops_sec": 22123.8
}
```

## Sample Benchmark Results

From `results.csv` (local Docker, 100 iterations):

| Service | Operation | Param Set | Avg Latency | Throughput |
|---------|-----------|-----------|-------------|------------|
| lattice_service | full_handshake | ml_kem_512 | 0.074 ms | 13,457 ops/sec |
| lattice_service | full_handshake | ml_kem_1024 | 0.142 ms | 7,063 ops/sec |
| zk_service | prove | multiply | 1.29 ms | 774 ops/sec |
| zk_service | verify | multiply | 0.41 ms | 2,431 ops/sec |

The ~17x throughput gap between ML-KEM and Groth16 proving illustrates how different cryptographic workloads scale.

## Benchmarking on Kubernetes

Two scripts are provided for running benchmarks on a Kubernetes cluster:

**`scripts/run-experiment.sh`** runs a single benchmark suite:

```bash
# Usage: ./scripts/run-experiment.sh <label> <lattice-replicas> <zk-replicas> <kem-iters> <zk-iters>
export REGISTRY=us-central1-docker.pkg.dev/your-project/pq-zk-bench

./scripts/run-experiment.sh baseline 1 1 500 50
./scripts/run-experiment.sh scaled-4x 4 4 500 50
```

**`scripts/full-experiment-matrix.sh`** runs a comprehensive parameter sweep:

```bash
export REGISTRY=us-central1-docker.pkg.dev/your-project/pq-zk-bench

# Optional: adjust experiment size
export RUNS_PER_CONFIG=3
export KEM_ITERATIONS=500
export ZK_ITERATIONS=50

./scripts/full-experiment-matrix.sh
```

This runs benchmarks across:
- All ML-KEM parameter sets (512, 768, 1024)
- All operations (keygen, encaps, decaps, full_handshake)
- ZK circuits (multiply, cube_root) for both proving and verification
- Concurrency levels (1, 2, 4, 8 concurrent requests)

Results are saved to `results/matrix-<timestamp>/` as JSONL files.

## Using as a Template

1. **Replace the crypto logic** in `lattice_service/` and `zk_service/` with your operations
2. **Keep the HTTP scaffolding**: the axum handlers, health endpoints, and response structures
3. **Adapt the Dockerfiles**: the caching pattern works for any Rust workspace
4. **Modify k8s manifests**: adjust resource limits for your workload's profile

## Tech Stack

- **Rust 1.83+** with async/await
- **axum** for HTTP routing
- **tokio** async runtime
- **serde** for JSON serialization
- **clap** for CLI argument parsing
- **ml-kem** (RustCrypto) for post-quantum KEM
- **arkworks** for ZK proofs

## License

MIT