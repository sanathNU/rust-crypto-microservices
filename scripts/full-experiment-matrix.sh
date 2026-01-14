#!/bin/bash
# Full experiment matrix for crypto-per-dollar analysis

set -e

# Registry configuration - set via environment or defaults for local
REGISTRY=${REGISTRY:-""}
IMAGE_TAG=${IMAGE_TAG:-"v1"}

if [ -z "$REGISTRY" ]; then
  BENCH_IMAGE="bench-client:${IMAGE_TAG}"
  echo "WARNING: REGISTRY not set, using local image: $BENCH_IMAGE"
  echo "For Kubernetes, set: export REGISTRY=us-central1-docker.pkg.dev/YOUR_PROJECT/pq-zk-bench"
else
  BENCH_IMAGE="${REGISTRY}/bench-client:${IMAGE_TAG}"
fi

NAMESPACE=${NAMESPACE:-"pq-zk-bench"}
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULTS_DIR="results/matrix-$TIMESTAMP"
mkdir -p $RESULTS_DIR

# Experiment configuration
RUNS_PER_CONFIG=${RUNS_PER_CONFIG:-3}
KEM_ITERATIONS=${KEM_ITERATIONS:-500}
ZK_ITERATIONS=${ZK_ITERATIONS:-50}

echo "=== Full Experiment Matrix ==="
echo "Results will be saved to $RESULTS_DIR"
echo ""

# Function to run and save benchmark
run_bench() {
  local LABEL=$1
  local SERVICE=$2
  local ARGS=$3
  
  echo "[$LABEL] Running..."
  
  kubectl delete job bench-matrix -n $NAMESPACE --ignore-not-found 2>/dev/null
  
  cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: bench-matrix
  namespace: $NAMESPACE
spec:
  ttlSecondsAfterFinished: 120
  template:
    spec:
      containers:
      - name: bench-client
        image: ${BENCH_IMAGE}
        args: [$ARGS]
      restartPolicy: Never
  backoffLimit: 1
EOF

  kubectl wait --for=condition=complete job/bench-matrix -n $NAMESPACE --timeout=600s 2>/dev/null
  kubectl logs -n $NAMESPACE job/bench-matrix >> "$RESULTS_DIR/$SERVICE.jsonl"
  sleep 5
}

# ============ KEM EXPERIMENTS ============
echo ""
echo "=== KEM Benchmarks ==="

for PARAM in ml_kem_512 ml_kem_768 ml_kem_1024; do
  for OP in keygen encaps decaps full_handshake; do
    for RUN in $(seq 1 $RUNS_PER_CONFIG); do
      LABEL="kem-${PARAM}-${OP}-run${RUN}"
      run_bench "$LABEL" "kem" "\"kem\", \"--url\", \"http://lattice-service:8000\", \"--param-set\", \"$PARAM\", \"--operation\", \"$OP\", \"--iterations\", \"$KEM_ITERATIONS\", \"--label\", \"$LABEL\""
    done
  done
done

# ============ ZK EXPERIMENTS ============
echo ""
echo "=== ZK Benchmarks ==="

for CIRCUIT in multiply cube_root; do
  # Proving
  for RUN in $(seq 1 $RUNS_PER_CONFIG); do
    LABEL="zk-prove-${CIRCUIT}-run${RUN}"
    run_bench "$LABEL" "zk" "\"zk-prove\", \"--url\", \"http://zk-service:8001\", \"--circuit-id\", \"$CIRCUIT\", \"--iterations\", \"$ZK_ITERATIONS\", \"--label\", \"$LABEL\""
  done
  
  # Verification
  for RUN in $(seq 1 $RUNS_PER_CONFIG); do
    LABEL="zk-verify-${CIRCUIT}-run${RUN}"
    run_bench "$LABEL" "zk" "\"zk-verify\", \"--url\", \"http://zk-service:8001\", \"--circuit-id\", \"$CIRCUIT\", \"--iterations\", \"$((ZK_ITERATIONS * 5))\", \"--label\", \"$LABEL\""
  done
done

# ============ CONCURRENCY EXPERIMENTS ============
echo ""
echo "=== Concurrency Scaling ==="

for CONCURRENCY in 1 2 4 8; do
  for REQUESTS in 1 10 50; do
    LABEL="kem-768-c${CONCURRENCY}-r${REQUESTS}"
    run_bench "$LABEL" "concurrency" "\"kem\", \"--url\", \"http://lattice-service:8000\", \"--param-set\", \"ml_kem_768\", \"--operation\", \"full_handshake\", \"--iterations\", \"100\", \"--requests\", \"$REQUESTS\", \"--concurrency\", \"$CONCURRENCY\", \"--label\", \"$LABEL\""
  done
done

echo ""
echo "=== Experiments Complete ==="
echo "Results saved to $RESULTS_DIR/"
echo ""
echo "To analyze, run:"
echo "  python scripts/analyze_results.py $RESULTS_DIR/"