#!/bin/bash
set -e

# Configuration
NAMESPACE="pq-zk-bench"
LABEL=${1:-"experiment"}
LATTICE_REPLICAS=${2:-1}
ZK_REPLICAS=${3:-1}
KEM_ITERATIONS=${4:-500}
ZK_ITERATIONS=${5:-50}

echo "=== Running Experiment: $LABEL ==="
echo "Lattice replicas: $LATTICE_REPLICAS"
echo "ZK replicas: $ZK_REPLICAS"

kubectl scale deployment/lattice-service -n $NAMESPACE --replicas=$LATTICE_REPLICAS
kubectl scale deployment/zk-service -n $NAMESPACE --replicas=$ZK_REPLICAS

kubectl rollout status deployment/lattice-service -n $NAMESPACE
kubectl rollout status deployment/zk-service -n $NAMESPACE

echo "Waiting 30s for services to stabilize..."
sleep 30

kubectl delete job bench-$LABEL -n $NAMESPACE --ignore-not-found


# Create benchmark job
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: bench-$LABEL
  namespace: $NAMESPACE
spec:
  ttlSecondsAfterFinished: 7200
  template:
    spec:
      containers:
      - name: bench-client
        image: us-central1-docker.pkg.dev/bold-oasis-474117-k8/pq-zk-bench/bench-client:v1
        args:
        - "suite"
        - "--lattice-url"
        - "http://lattice-service:8000"
        - "--zk-url"
        - "http://zk-service:8001"
        - "--kem-iterations"
        - "$KEM_ITERATIONS"
        - "--zk-iterations"
        - "$ZK_ITERATIONS"
        - "--label"
        - "$LABEL"
      restartPolicy: Never
  backoffLimit: 2
EOF

# Wait for job to complete
echo "Waiting for benchmark to complete..."
kubectl wait --for=condition=complete job/bench-$LABEL -n $NAMESPACE --timeout=600s

# Get results
echo ""
echo "=== Results for $LABEL ==="
kubectl logs -n $NAMESPACE job/bench-$LABEL

# Save results to file
kubectl logs -n $NAMESPACE job/bench-$LABEL > "results-$LABEL.json"
echo "Results saved to results-$LABEL.json"