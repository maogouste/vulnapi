# VulnAPI Cross-Implementation Tests

Tests GraphQL vulnerabilities (G01-G05) across all VulnAPI implementations.

## Tested Vulnerabilities

| ID  | Vulnerability          | Description                               |
|-----|------------------------|-------------------------------------------|
| G01 | Introspection          | Schema exposed via `__schema` query       |
| G02 | No Depth Limit         | Deep nested queries allowed (DoS vector)  |
| G03 | Batching               | Multiple queries processed without limits |
| G04 | Field Suggestions      | Error messages reveal valid field names   |
| G05 | Auth Bypass            | Sensitive data accessible without auth    |

## Backends

| Backend | Port | URL                      |
|---------|------|--------------------------|
| Python  | 3001 | http://localhost:3001    |
| Go      | 3002 | http://localhost:3002    |
| PHP     | 3003 | http://localhost:3003    |
| Java    | 3004 | http://localhost:3004    |
| Node    | 3005 | http://localhost:3005    |

## Prerequisites

```bash
# Install dependencies
pip install -r requirements.txt

# Or use existing venv
source ../implementations/python-fastapi/venv/bin/activate
```

## Running Tests

### Test All Backends
```bash
# Start all backends first
cd ../implementations/python-fastapi && ./start.sh &
cd ../implementations/go-gin && go run main.go &
cd ../implementations/php-laravel && php -S localhost:3003 &
cd ../implementations/java-spring && mvn spring-boot:run &
cd ../implementations/node-express && npm start &

# Run tests
pytest cross-implementation/ -v
```

### Test Specific Backend
```bash
# Using environment variable
VULNAPI_BACKENDS=python pytest cross-implementation/ -v
VULNAPI_BACKENDS=go,php pytest cross-implementation/ -v

# Using the script
./cross-implementation/run_tests.sh python
./cross-implementation/run_tests.sh go php java
```

### Test Specific Vulnerability
```bash
pytest cross-implementation/ -v -k "G01"
pytest cross-implementation/ -v -k "G02 or G03"
pytest cross-implementation/ -v -k "test_G05_users_query_without_auth"
```

### Combined Filters
```bash
# Test G01 on Go and PHP only
VULNAPI_BACKENDS=go,php pytest cross-implementation/ -v -k "G01"
```

## Test Output

Tests print vulnerability findings:
```
[python] G01 VULNERABLE: Found 15 types via introspection
[python] G02 VULNERABLE: Deep nested query accepted
[python] G03 VULNERABLE: 5 batched queries executed
[python] G04 VULNERABLE: Field suggestions enabled
[python] G05 VULNERABLE: 3 users exposed without auth
```

Summary test shows all vulnerabilities at once:
```
[python] VULNERABILITY SUMMARY:
  G01_introspection: VULNERABLE
  G02_depth: VULNERABLE
  G03_batching: VULNERABLE
  G04_suggestions: VULNERABLE
  G05_auth_bypass: VULNERABLE
  Total: 5/5 vulnerabilities present
```

## Test Count

- 15 test methods
- 5 backends
- **75 total tests** (15 × 5)

## Auto-Skip

Tests automatically skip for backends that are not running. No configuration needed.
