# Sentinel-API — QuickStart Guide

> Go scanner · Python AI · NVD CVE · HTMX dashboard · v2.4.1

---

## Prerequisites

| Requirement | Min version | Notes |
|---|---|---|
| Go | 1.22+ | Scanner engine |
| Python | 3.11+ | AI layer + UI server |
| Docker + Compose | 24+ | Full-stack deployment |
| RAM | 8 GB | 16 GB recommended for local LLM |
| Disk | 5 GB | ~4 GB for Mistral-7B model |

---

## 1. Clone the repository

```bash
git clone https://github.com/david-spies/sentinel-api
cd sentinel-api
```

---

## 2. Build the Go scanner

```bash
cd scanner
go mod tidy
go build -o sentinel-api ./cmd/main.go
./sentinel-api version    # sentinel-api v2.4.1
cd ..
```

---

## 3. Download the LLM model

The AI layer uses Mistral-7B-Instruct-v0.2 (Q4 quantised, ~4 GB) running entirely on your machine — no API keys, no data leaves.

```bash
make download-model
# Downloads to ./models/mistral-7b-instruct-v0.2.Q4_K_M.gguf
```

Manual download:
```bash
mkdir -p models
curl -L "https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf" \
  -o models/mistral-7b-instruct-v0.2.Q4_K_M.gguf
```

---

## 4. Generate gRPC stubs

The Go scanner and Python AI service communicate over gRPC. Stubs must be generated once from `proto/sentinel.proto`:

```bash
make proto
# Generates:  ai/grpc/sentinel_pb2.py
#             ai/grpc/sentinel_pb2_grpc.py
#             scanner/internal/grpc/sentinelpb/*.go
```

Requires `grpcio-tools` (Python) and `protoc` + `protoc-gen-go` + `protoc-gen-go-grpc` (Go). The `Makefile` handles all targets.

---

## 5. Start the full stack

```bash
make up
# or: docker compose up -d ai ui
```

| Service | URL | Purpose |
|---|---|---|
| Dashboard | http://localhost:3000 | HTMX scan interface |
| AI backend | http://localhost:8000 | FastAPI + LLM |
| AI backend docs | http://localhost:8000/docs | Available in dev mode |
| gRPC | localhost:50051 | Scanner↔AI transport |

Wait for the AI backend to finish loading the model (~20–30 s on CPU):

```bash
curl http://localhost:8000/health
# {"status":"ok","model_loaded":true,"model_name":"mistral-7b-instruct-v0.2.Q4_K_M","uptime_s":45.2,...}
```

---

## 6. Run your first scan

### Option A — Browser (recommended)

1. Open **http://localhost:3000**
2. Click **New Scan** or use the Quick Scan form on the overview page
3. Enter your target URL, optional Bearer token, and check **NVD CVE Lookup**
4. Click **Launch Scan** — the progress log streams live via WebSocket
5. When complete, click **View Results** to see the full report

### Option B — CLI

```bash
# Unauthenticated scan with OWASP checks + NVD CVE lookup
./scanner/sentinel-api scan \
  --target https://api.example.com \
  --nvd-lookup \
  --output ./reports

# Authenticated full scan with gRPC AI integration
./scanner/sentinel-api scan \
  --target https://api.example.com \
  --token "eyJhbGciOiJSUzI1NiJ9..." \
  --openapi https://api.example.com/openapi.json \
  --nvd-lookup \
  --nvd-api-key "YOUR-NVD-KEY" \
  --ai-backend grpc://localhost:50051 \
  --output ./reports

# Fast discovery-only (no OWASP, no NVD)
./scanner/sentinel-api scan \
  --target https://api.example.com \
  --no-owasp --no-rate-test \
  --concurrency 50

# CI/CD gate — exits 1 on any critical finding
./scanner/sentinel-api scan \
  --target https://staging.api.example.com \
  --no-color \
  --output ./reports
echo "Exit code: $?"
```

Reports appear in `./reports/`:
- `sentinel_<id>.json` — full machine-readable `ScanResult`
- `sentinel_<id>.md` — human audit report with CVE table and AI remediation

---

## 7. Register an NVD API key (optional but recommended)

The NVD API allows 5 requests per 30 seconds without a key, 50 with one. Register free:

1. Visit https://nvd.nist.gov/developers/request-an-api-key
2. Enter your email; key arrives within minutes
3. Pass via `--nvd-api-key YOUR-KEY` or set in `sentinel-api.yaml`:

```yaml
nvd_api_key: "your-key-here"
scan_modes:
  cve_lookup: true
```

---

## 8. Configuration file

Copy `scanner/configs/sentinel-api.yaml` and customise:

```yaml
target: https://api.example.com
concurrency: 30
rate_limit_rps: 30
timeout: 10s

bearer_token: "eyJhbGci..."
openapi_spec_url: https://api.example.com/openapi.json

nvd_api_key: "your-nvd-key"
nvd_timeout: 15s
nvd_cache_ttl: 24h

scan_modes:
  discovery:     true
  owasp:         true
  rate_limit:    true
  pii_detection: true
  shadow_api:    true
  cve_lookup:    true   # live NVD lookup
  fuzzing:       false

output_path: ./reports
ai_backend_url: grpc://localhost:50051
```

```bash
./scanner/sentinel-api scan --config ./my-scan.yaml
```

---

## 9. Dashboard walkthrough

After a scan completes, go to **http://localhost:3000/results/{scan_id}**.

### Tabs

| Tab | Source | What it shows |
|---|---|---|
| **Findings** | `models.Finding[]` | Collapsible cards — severity, OWASP category, CVSS, evidence, AI remediation code |
| **Endpoints** | `models.Endpoint[]` | All discovered endpoints with filter chips (All / Shadow / Zombie / Internal) |
| **OWASP Top 10** | `owasp_checks.go` | 10-cell grid — pass/warn/fail bars with check function name per category |
| **Shadow APIs** | `detectShadows()` | Undocumented and zombie endpoints with risk scores |
| **CVE / NVD** | `nvd.LookupServer()` | Full CVE table — CVSS v4.0/v3.1, CISA KEV badge, CWEs, references |
| **Rate Probes** | `probeRateLimit()` | TTFB degradation bars — RecursiveRisk (>200%) highlighted in red |
| **Directory** | `BuildDirectoryTree()` | SentinelRank virtual directory — ROOT/Auth-AuthZ/, ROOT/CVE-Infrastructure/, etc. |

### History page

Go to **http://localhost:3000/history** to see all past scans. Filter by target to see:
- **Score trend chart** — SentinelRank over time with critical finding overlay
- **OWASP coverage chart** — max risk score per category (horizontal bar)

---

## 10. Scan pipeline — what runs when

| Stage | Code | What happens |
|---|---|---|
| **0a Fingerprint** | `engine/client.go → Fingerprint()` | Probes 7 paths · captures TLS via `VerifyConnection()` · detects WAF/gateway/language |
| **0b CVE lookup** | `nvd/client.go → LookupServer()` | Parses banner → CPE queries → NVD API 2.0 → CISA KEV cross-ref → cache |
| **0b CVE inject** | `nvd/findings.go → CVEToFindings()` | CVSS ≥7.0 or KEV entries become `models.Finding` with OWASP API8 category |
| **1 Discovery** | `discovery/enumerator.go` | 25 goroutines · 200-path wordlist · auth enrichment · shadow detection |
| **2 OWASP** | `analyzer/owasp_checks.go` | 8 check functions · PII regex scan · rate-limit burst test |
| **3 Score** | `analyzer/sentinel_rank.go` | `ScoreFinding()` · `BuildDirectoryTree()` · `ScoreScan()` |
| **3 Report** | `reporter/reporter.go` | Write JSON + MD · POST to AI backend · back-fill remediation |

---

## 11. Developing the UI

```bash
cd ui
pip install -r requirements.txt
AI_BACKEND_URL=http://localhost:8000 uvicorn ui.main:app --reload --port 3000
```

HTMX partial templates live in `ui/templates/partials/`. Each partial is a standalone HTML fragment — edit and the browser reflects changes on next poll/swap without restarting the server.

---

## 12. Running tests

```bash
# Go scanner (unit + integration)
cd scanner && go test ./...

# Python AI layer
make test             # all
make test-unit        # SentinelRank scoring engine only
make test-api         # FastAPI HTTP endpoints only
make test-coverage    # with HTML coverage report

# gRPC smoke test (requires running AI backend)
grpcurl -plaintext localhost:50051 sentinel.SentinelAI/Health
```

---

## 13. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Dashboard shows "offline" | AI backend not started | `docker compose up -d ai` or `make dev-ai` |
| Model still loading after 60s | Large model, slow CPU | Wait — Q4 loads in ~25 s on 8-thread CPU; use GPU build for instant load |
| `--nvd-lookup` returns 0 CVEs | NVD rate limit hit | Add `--nvd-api-key` or wait 30 s between scans |
| NVD timeout errors | Slow or blocked connection | Use `--nvd-offline` for air-gapped environments |
| Scan log stops mid-progress | WebSocket disconnected | Check UI server is running and AI backend is healthy |
| `protoc` not found | gRPC stubs not generated | Install `protoc` + `protoc-gen-go`; run `make proto` |
| `go: cannot find module` | Dependencies not downloaded | Run `cd scanner && go mod tidy` |
| Port 50051 refused | gRPC server not started | AI backend starts gRPC on port 50051 — ensure it started cleanly |
| Empty findings in dashboard | Wrong scan_id | Check `./reports/` for `sentinel_*.json` files |

---

*Sentinel-API v2.4.1 · Go 1.22 · Python 3.11 · HTMX 1.9 · OWASP API Security Top 10 (2023)*
