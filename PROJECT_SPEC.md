# VulnAPI - Intentionally Vulnerable API

## Project Vision

VulnAPI is an educational platform demonstrating security bad practices in APIs. It allows learners to understand, exploit, and fix common vulnerabilities listed in the OWASP API Security Top 10.

## Educational Goals

- Illustrate API vulnerabilities in a controlled environment
- Compare attack vectors between REST and GraphQL
- Enable learning by doing (challenge mode)
- Provide detailed explanations (documentation mode)

---

## 4-Phase Architecture

### Phase 1: REST API + Challenges

**Goal**: Functional foundation with vulnerable REST endpoints

**Deliverables**:
- REST API with JWT authentication (intentionally poorly implemented)
- Database with fictional data
- Flag/challenge system
- OpenAPI documentation

**Vulnerabilities to implement**:
| ID | Vulnerability | Example Endpoint |
|----|---------------|------------------|
| V01 | Broken Object Level Authorization (BOLA) | `GET /api/users/{id}` |
| V02 | Broken Authentication | `POST /api/login` |
| V03 | Excessive Data Exposure | `GET /api/users/me` |
| V04 | Lack of Rate Limiting | `POST /api/login` |
| V05 | Mass Assignment | `PUT /api/users/me` |
| V06 | SQL Injection | `GET /api/products?search=` |
| V07 | Command Injection | `POST /api/tools/ping` |
| V08 | Security Misconfiguration | Headers, CORS |
| V09 | Improper Assets Management | `GET /api/v1/` vs `/api/v2/` |
| V10 | Insufficient Logging | Missing audit trails |

### Phase 2: GraphQL + Extended Challenges

**Goal**: Add a GraphQL layer with specific vulnerabilities

**Deliverables**:
- `/graphql` endpoint with complete schema
- GraphQL-specific vulnerabilities
- Additional challenges

**GraphQL-specific vulnerabilities**:
| ID | Vulnerability | Description |
|----|---------------|-------------|
| G01 | Exposed introspection | Schema accessible in production |
| G02 | Nested queries (DoS) | Unlimited nested queries |
| G03 | Batching attacks | Multiple operations in one request |
| G04 | Field suggestions | Aids enumeration |
| G05 | Authorization bypass | Missing checks on resolvers |

### Phase 3: Documentation Mode

**Goal**: Add educational explanations

**Deliverables**:
- Challenge/documentation toggle in the API
- Detailed explanations for each vulnerability
- Vulnerable vs secure code examples
- OWASP and CWE references

**Documentation structure per vulnerability**:
```
{
  "id": "V01",
  "name": "Broken Object Level Authorization",
  "description": "...",
  "vulnerable_code": "...",
  "secure_code": "...",
  "exploitation": "...",
  "remediation": "...",
  "references": ["OWASP API1:2023", "CWE-639"]
}
```

### Phase 4: Introduction Frontend

**Goal**: Web interface to guide beginners

**Deliverables**:
- Dashboard with progress tracking
- Interface to test endpoints
- Request/response visualization
- Interactive tutorials

---

## Tech Stack

### Main Implementation: Python

```
python-fastapi/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # Configuration
│   ├── database.py          # DB connection
│   │
│   ├── models/              # SQLAlchemy models
│   │   ├── user.py
│   │   ├── product.py
│   │   └── order.py
│   │
│   ├── schemas/             # Pydantic schemas
│   │   └── ...
│   │
│   ├── routers/             # REST endpoints
│   │   ├── auth.py
│   │   ├── users.py
│   │   ├── products.py
│   │   └── tools.py
│   │
│   ├── graphql/             # GraphQL schema (Phase 2)
│   │   ├── schema.py
│   │   ├── queries.py
│   │   └── mutations.py
│   │
│   ├── challenges/          # Flag system
│   │   ├── flags.py
│   │   └── validator.py
│   │
│   ├── docs/                # Documentation mode (Phase 3)
│   │   └── vulnerabilities.json
│   │
│   └── vulnerabilities/     # Isolated vulnerable code
│       ├── bola.py
│       ├── sqli.py
│       └── ...
│
├── tests/
│   ├── exploits/            # Exploitation scripts
│   └── unit/
│
├── docker-compose.yaml
├── Dockerfile
├── requirements.txt
└── README.md
```

### Python Dependencies (Phase 1)

```
fastapi>=0.109.0
uvicorn>=0.27.0
sqlalchemy>=2.0.0
pydantic>=2.0.0
python-jose>=3.3.0          # JWT
passlib>=1.7.0              # Hashing (intentionally misused)
python-multipart>=0.0.6
```

### Additional Dependencies (Phase 2)

```
strawberry-graphql>=0.217.0  # GraphQL
```

---

## Shared API Contract

To facilitate reimplementations in other languages, an OpenAPI contract will be maintained:

```
specs/
├── openapi.yaml             # REST specification
├── graphql.schema           # GraphQL schema
├── challenges.json          # Challenge/flag definitions
├── test-suite/              # Portable exploitation tests
│   ├── test_bola.py
│   ├── test_sqli.py
│   └── ...
└── data/
    └── seed.sql             # Shared initial data
```

---

## Future Reimplementations

The project is designed to be reimplemented in other languages:

| Priority | Language | Framework | Justification |
|----------|---------|-----------|---------------|
| 1 | Python | FastAPI | Reference implementation |
| 2 | JavaScript | Express.js | Very popular, large ecosystem |
| 3 | Java | Spring Boot | Enterprise context |
| 4 | Go | Gin | Cloud-native, modern |
| 5 | PHP | Laravel | Legacy, still very present |

### Rules for reimplementations

1. **Follow the OpenAPI contract** — Same endpoints, same responses
2. **Same vulnerabilities** — Identical exploitable behavior
3. **Same flags** — Enable the same challenges
4. **Shared tests** — Pass the same exploitation test suite
5. **Similar structure** — Facilitate comparison between implementations

---

## Development Environment

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- SQLite (dev) / PostgreSQL (prod)

### Quick Start

```bash
# Clone the project
git clone <repo>
cd vulnapi

# Virtual environment
python -m venv venv
source venv/bin/activate

# Dependencies
pip install -r requirements.txt

# Start the API
uvicorn app.main:app --reload

# Or via Docker
docker-compose up
```

### Environment Variables

```
VULNAPI_MODE=challenge|documentation
VULNAPI_DB_URL=sqlite:///./vulnapi.db
VULNAPI_SECRET_KEY=intentionally-weak-secret
VULNAPI_DEBUG=true
```

---

## Context for Claude

### For future sessions, remember:

1. **Project**: VulnAPI - Intentionally vulnerable API for learning
2. **Current phase**: Phase 1 completed (REST + Challenges)
3. **Stack**: Python/FastAPI, then multi-language
4. **Approach**: Incremental, each phase delivers value
5. **Reference file**: This document `PROJECT_SPEC.md`

### Useful commands for Claude

- "Continue VulnAPI development phase X"
- "Add vulnerability Y to the REST API"
- "Prepare the reimplementation in [language]"
- "Generate exploitation tests for vulnerability Z"

---

## License and Disclaimer

**WARNING**: This software is designed for educational purposes only. Vulnerabilities are intentional. Never deploy in production or use against systems without authorization.

**License**: [TBD - MIT / GPL / etc.]

---

## Decision History

| Date | Decision |
|------|----------|
| 2026-01-11 | Project creation, 4-phase approach chosen |
| 2026-01-11 | Python/FastAPI as reference implementation |
| 2026-01-11 | Multi-language architecture planned from the start |
| 2026-01-11 | Phase 1 completed: REST API + 10 OWASP vulnerabilities + flag system |
