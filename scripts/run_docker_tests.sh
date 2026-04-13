#!/bin/bash
# Run Docker-based integration tests for pgloglens
#
# Usage: ./scripts/run_docker_tests.sh
#
# Prerequisites:
#   - Docker and docker-compose installed
#   - psycopg2 installed (pip install psycopg2-binary)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=============================================="
echo "pgloglens Docker Integration Tests"
echo "=============================================="

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    exit 1
fi

# Start PostgreSQL container
echo ""
echo "[1/5] Starting PostgreSQL container..."
docker-compose up -d postgres

# Wait for PostgreSQL to be healthy
echo ""
echo "[2/5] Waiting for PostgreSQL to be ready..."
for i in {1..30}; do
    if docker-compose exec -T postgres pg_isready -U testuser -d testdb > /dev/null 2>&1; then
        echo "PostgreSQL is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "Error: PostgreSQL did not become ready in time"
        docker-compose logs postgres
        docker-compose down
        exit 1
    fi
    sleep 1
done

# Generate test logs
echo ""
echo "[3/5] Generating test logs..."
if ! python -c "import psycopg2" 2>/dev/null; then
    echo "Installing psycopg2-binary..."
    pip install psycopg2-binary
fi

python tests/docker/generate_logs.py

# Copy logs from container
echo ""
echo "[4/5] Copying logs from container..."
mkdir -p tests/docker
docker cp pgloglens-test-pg:/var/log/postgresql/postgresql.log tests/docker/postgresql.log

# Show log stats
LOG_FILE="tests/docker/postgresql.log"
if [ -f "$LOG_FILE" ]; then
    LINE_COUNT=$(wc -l < "$LOG_FILE")
    SIZE=$(du -h "$LOG_FILE" | cut -f1)
    echo "Log file: $LOG_FILE"
    echo "Lines: $LINE_COUNT"
    echo "Size: $SIZE"
fi

# Run tests
echo ""
echo "[5/5] Running integration tests..."
pytest tests/test_integration.py -v --docker

# Show test log analysis
echo ""
echo "=============================================="
echo "Sample analysis of generated logs:"
echo "=============================================="
python -m pgloglens.cli analyze tests/docker/postgresql.log --format json | python -c "
import json
import sys
data = json.load(sys.stdin)
print(f\"Total entries analyzed\")
print(f\"Slow queries: {len(data.get('slow_queries', []))}\")
print(f\"Error patterns: {len(data.get('error_patterns', []))}\")
print(f\"RCA findings: {len(data.get('rca_findings', []))}\")
"

# Cleanup option
echo ""
read -p "Stop and remove containers? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker-compose down -v
    echo "Containers stopped and removed"
fi

echo ""
echo "Done!"
