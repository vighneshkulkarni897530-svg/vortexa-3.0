# PromptShield Deployment Guide

This document outlines deployment procedures for **PromptShield (VORTEXA 3.0, Track C-03)** across containerized (Docker Compose) and standalone multi-service configurations.

---

## 1. Architecture Overview & Network Topology

PromptShield operates as a high-assurance AI security gateway between untrusted external clients (user prompts, uploaded documents, web scraper outputs) and protected Large Language Model (LLM) adapters.

```
                     ┌────────────────────────────────────────┐
                     │          Client Browser / UI           │
                     │          (Port 3000 or Port 80)        │
                     └───────────────────┬────────────────────┘
                                         │ HTTP
                                         ▼
                     ┌────────────────────────────────────────┐
                     │          Reverse Proxy (Nginx)         │
                     │         Reverse Proxies /api/v1        │
                     └─────────┬────────────────────┬─────────┘
                               │                    │
            /api/v1/scan,      │                    │ /api/v1/policies,
            /api/v1/benchmark  │                    │ /api/v1/review-queue,
                               ▼                    │ /api/v1/audit-events
        ┌─────────────────────────────┐             ▼
        │   Detection Engine Service  │  HTTP  ┌─────────────────────────────┐
        │   (Laptop 2 - Port 8000)    ├───────►│  Policy & Database Service  │
        │   FastAPI / Invariant Guard │        │   (Laptop 3 - Port 8001)    │
        └──────────────┬──────────────┘        │   FastAPI / Policy Engine   │
                       │                       └──────────────┬──────────────┘
                       ▼                                      │
        ┌─────────────────────────────┐                       ▼
        │  Mock / Real LLM Adapter    │        ┌─────────────────────────────┐
        │  (Authorized Content Only)  │        │   PostgreSQL 16 Database    │
        └─────────────────────────────┘        │   (Port 5432 - Persistent)  │
                                               └─────────────────────────────┘
```

---

## 2. Docker Compose Deployment (Recommended for Production)

### 2.1 Prerequisites
- Docker Engine 24.0+ and Docker Compose v2.20+
- Port availability: `8000` (Detection), `8001` (Policy), `3000` (Frontend), `5432` (PostgreSQL)

### 2.2 Environment Configuration
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Ensure placeholder secrets are replaced with production-grade random values:
- `JWT_SECRET_KEY`: Generate via `python -c "import secrets; print(secrets.token_hex(32))"`
- `POSTGRES_PASSWORD`: Strong master password for the database.
- `MOCK_LLM_MODE`: Set to `true` for credential-free demonstration, or `false` when connecting OpenAI/Gemini credentials.

### 2.3 Single-Command Startup
```powershell
docker compose up -d --build
```

### 2.4 Service Verification & Health Checks
Inspect running containers and health status:
```powershell
docker compose ps
```
Verify individual health check endpoints:
```powershell
# Detection Engine Health
Invoke-RestMethod -Uri "http://localhost:8000/health"

# Policy Service Health & DB Ping
Invoke-RestMethod -Uri "http://localhost:8001/api/v1/health"

# Frontend Static Gateway
Invoke-WebRequest -Uri "http://localhost:3000/" -Method Head
```

### 2.5 Running In-Container Evaluation Tests
Execute the regression test suite inside the container network:
```powershell
docker compose --profile test run --rm test-runner
```

### 2.6 Shutdown & Cleanup
Graceful shutdown preserving database volumes:
```powershell
docker compose down
```
Complete teardown including volumes (WARNING: Deletes persistent test data):
```powershell
docker compose down -v
```

---

## 3. Standalone / Distributed Deployment (Laptop-by-Laptop)

For multi-machine testing or separate microservice deployments:

### 3.1 Policy & Database Service (Laptop 3)
1. Configure PostgreSQL database or local SQLite:
   ```powershell
   $env:DATABASE_URL = "postgresql+psycopg://promptshield_user:promptshield_secure_pass@localhost:5432/promptshield_db"
   $env:JWT_SECRET_KEY = "your-secure-production-jwt-key"
   $env:FAIL_SECURE_MODE = "true"
   ```
2. Execute Alembic migrations:
   ```powershell
   alembic upgrade head
   ```
3. Start the Policy API on port 8001:
   ```powershell
   uvicorn promptshield.main:app --host 0.0.0.0 --port 8001
   ```

### 3.2 Detection Engine Service (Laptop 2)
1. Point to Laptop 3's authoritative Policy endpoint:
   ```powershell
   $env:POLICY_SERVICE_URL = "http://<LAPTOP_3_IP>:8001"
   $env:POLICY_TIMEOUT_SECONDS = "2.0"
   $env:MOCK_LLM_MODE = "true"
   ```
2. Start the Detection API on port 8000:
   ```powershell
   uvicorn backend.main:app --host 0.0.0.0 --port 8000
   ```

### 3.3 Frontend Dashboard (Laptop 1)
1. Update `frontend/app.js` with the network addresses:
   ```javascript
   const API_BASE_DETECTION = "http://<LAPTOP_2_IP>:8000";
   const API_BASE_POLICY = "http://<LAPTOP_3_IP>:8001";
   ```
2. Serve via Nginx or Python static HTTP server:
   ```powershell
   python -m http.server 3000 --directory frontend
   ```

---

## 4. CORS & Security Hardening Configuration

In production environments:
1. **CORS Whitelisting**: Ensure `backend/main.py` and `promptshield/main.py` restrict `allow_origins` to your production frontend domain (e.g., `https://promptshield.enterprise.org`) rather than `["*"]`.
2. **Reverse Proxy TLS Termination**: Terminate HTTPS at the Nginx ingress or corporate load balancer using valid TLS certificates.
3. **Fail-Secure Verification**: Ensure `$env:FAIL_SECURE_MODE = "true"` so that network interruptions between Laptop 2 and Laptop 3 result in deterministic `BLOCK` actions rather than open bypass.
4. **Synthetic Canaries**: Never use live production API keys or credentials in test fixtures. Synthetic canary tokens (`CANARY_VORTEXA_SEC_7749`) trigger detection rules without exposing production assets.
