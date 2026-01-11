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

## Project Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | REST API + Challenges | Completed |
| 2 | GraphQL | Planned |
| 3 | Documentation Mode | Planned |
| 4 | Frontend | Planned |

## Documentation

See [PROJECT_SPEC.md](PROJECT_SPEC.md) for the full specification.

## License

[TBD]
