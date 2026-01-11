# VulnAPI

Intentionally vulnerable API for learning API security.

## Warning

This software contains **intentional** vulnerabilities for educational purposes.
**Never deploy in production.**

## Goals

- Understand OWASP API Security Top 10 vulnerabilities
- Practice exploitation in a controlled environment
- Compare REST vs GraphQL attack vectors
- Learn how to secure your APIs

## Project Structure

```
vulnapi/
├── specs/                    # Shared API contract (OpenAPI, tests)
├── implementations/
│   └── python-fastapi/       # Reference implementation
└── PROJECT_SPEC.md           # Full project specification
```

## Quick Start

```bash
cd implementations/python-fastapi

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Start the API
uvicorn app.main:app --reload
```

The API will be available at `http://localhost:8000`

### Frontend (Optional)

```bash
cd frontend
npm install
npm run dev
```

The frontend will be available at `http://localhost:3000`

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/docs` | Swagger UI documentation |
| `/api/*` | REST API endpoints |
| `/graphql/` | GraphQL endpoint + GraphiQL UI |

## Project Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | REST API + Challenges (V01-V10) | Completed |
| 2 | GraphQL + Challenges (G01-G05) | Completed |
| 3 | Documentation Mode | Completed |
| 4 | Frontend (React/Vite) | Completed |

## API Modes

VulnAPI supports two modes:

- **Challenge Mode** (default): Limited information, find vulnerabilities yourself
- **Documentation Mode**: Full exploitation details, code examples, and remediation

Switch modes with the environment variable:
```bash
# Challenge mode (default)
VULNAPI_MODE=challenge uvicorn app.main:app

# Documentation mode
VULNAPI_MODE=documentation uvicorn app.main:app
```

## Challenges

### REST API (V01-V10)
- V01: Broken Object Level Authorization (BOLA)
- V02: Broken Authentication (JWT)
- V03: Excessive Data Exposure
- V04: Lack of Rate Limiting
- V05: Mass Assignment
- V06: SQL Injection
- V07: Command Injection
- V08: Security Misconfiguration
- V09: Improper Assets Management
- V10: Insufficient Logging

### GraphQL (G01-G05)
- G01: Introspection Exposed
- G02: Nested Queries (DoS)
- G03: Batching Attacks
- G04: Field Suggestions
- G05: Authorization Bypass

## Documentation

See [PROJECT_SPEC.md](PROJECT_SPEC.md) for the full specification.

## License

[TBD]
