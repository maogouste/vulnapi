# Installing VulnAPI

## Prerequisites

### Python
- Python 3.10 or higher
- pip

### System Dependencies (for injection vulnerabilities)
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y iputils-ping dnsutils

# Arch Linux
sudo pacman -S iputils bind-tools

# RHEL/CentOS
sudo dnf install -y iputils bind-utils
```

## Installation

### 1. Clone the project
```bash
git clone <repo-url>
cd vulnapi
```

### 2. Create virtual environment
```bash
cd implementations/python-fastapi

# Create venv
python3 -m venv venv

# Activate venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows
```

### 3. Install dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configuration (optional)
```bash
# Copy example file
cp .env.example .env

# Edit if needed
nano .env
```

### 5. Start the application
```bash
# Development mode with auto-reload
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Production mode
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 6. Access the API
- Swagger Documentation: http://localhost:8000/docs
- ReDoc Documentation: http://localhost:8000/redoc
- API Root: http://localhost:8000/

## Docker Installation

```bash
# From project root
docker-compose up -d

# Logs
docker-compose logs -f vulnapi-python
```

## Verify Installation

```bash
# Test that the API responds
curl http://localhost:8000/health

# Expected response:
# {"status":"healthy","debug":true}
```

## Troubleshooting

### "Module not found" error
```bash
# Make sure venv is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Error with ping/nslookup (V07)
Command injection vulnerabilities require these tools:
```bash
which ping    # Should return a path
which nslookup
```

### Port already in use
```bash
# Change the port
uvicorn app.main:app --port 8001
```

### Corrupted database
```bash
# Delete and restart (will be recreated automatically)
rm vulnapi.db
uvicorn app.main:app --reload
```

## Security Notes

**WARNING**: This application contains intentional vulnerabilities.

- NEVER expose on the Internet without protection
- Use only in an isolated environment
- Ideal: Dedicated VM or Docker container
