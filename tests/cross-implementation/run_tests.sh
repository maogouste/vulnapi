#!/bin/bash
#
# Run GraphQL G01-G05 cross-implementation tests
#
# Usage:
#   ./run_tests.sh                    # Test all backends
#   ./run_tests.sh python             # Test only Python
#   ./run_tests.sh go php             # Test Go and PHP
#   ./run_tests.sh -k G01             # Test only G01 vulnerability
#   ./run_tests.sh python -k "G02 or G03"  # Combine backend and test filters
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VULNAPI_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
TESTS_DIR="$SCRIPT_DIR"

# Default: test all backends
BACKENDS="python,go,php,java,node"
PYTEST_ARGS=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        python|go|php|java|node)
            if [[ "$BACKENDS" == "python,go,php,java,node" ]]; then
                BACKENDS="$1"
            else
                BACKENDS="$BACKENDS,$1"
            fi
            shift
            ;;
        -k|--keyword)
            PYTEST_ARGS="$PYTEST_ARGS -k \"$2\""
            shift 2
            ;;
        -v|--verbose)
            PYTEST_ARGS="$PYTEST_ARGS -v"
            shift
            ;;
        -s|--show-output)
            PYTEST_ARGS="$PYTEST_ARGS -s"
            shift
            ;;
        *)
            PYTEST_ARGS="$PYTEST_ARGS $1"
            shift
            ;;
    esac
done

# Export backends to test
export VULNAPI_BACKENDS="$BACKENDS"

echo "=========================================="
echo "VulnAPI GraphQL G01-G05 Tests"
echo "=========================================="
echo "Testing backends: $BACKENDS"
echo ""

# Check which backends are running
echo "Backend status:"
for backend in python go php java node; do
    case $backend in
        python) PORT=3001 ;;
        go) PORT=3002 ;;
        php) PORT=3003 ;;
        java) PORT=3004 ;;
        node) PORT=3005 ;;
    esac

    if curl -s -o /dev/null -w "%{http_code}" "http://localhost:$PORT/api/health" | grep -q "200"; then
        echo "  $backend (port $PORT): RUNNING"
    else
        echo "  $backend (port $PORT): NOT RUNNING"
    fi
done
echo ""

# Activate venv if exists
if [[ -f "$VULNAPI_DIR/implementations/python-fastapi/venv/bin/activate" ]]; then
    source "$VULNAPI_DIR/implementations/python-fastapi/venv/bin/activate"
fi

# Run tests
echo "Running tests..."
echo ""
eval pytest "$TESTS_DIR/test_graphql_vulnerabilities.py" -v $PYTEST_ARGS

# Exit code
exit $?
