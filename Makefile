# Sentinel-API AI Layer — Makefile
# Usage: make <target>

PROTO_SRC    := proto/sentinel.proto
PROTO_PY_OUT := ai/grpc
PROTO_GO_OUT := scanner/internal/grpc/sentinelpb
MODEL_URL    := https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.2-GGUF/resolve/main/mistral-7b-instruct-v0.2.Q4_K_M.gguf
MODEL_PATH   := models/mistral-7b-instruct-v0.2.Q4_K_M.gguf

.PHONY: proto proto-py proto-go test test-unit test-api lint \
        download-model build-ai build-scanner up down logs clean help

# ---------------------------------------------------------------------------
# Proto codegen
# ---------------------------------------------------------------------------

proto: proto-py proto-go ## Generate protobuf stubs for Python and Go

proto-py: ## Generate Python gRPC stubs from proto/sentinel.proto
	@echo "→ Generating Python stubs..."
	@mkdir -p $(PROTO_PY_OUT)
	python -m grpc_tools.protoc \
		-I proto \
		--python_out=$(PROTO_PY_OUT) \
		--grpc_python_out=$(PROTO_PY_OUT) \
		$(PROTO_SRC)
	@touch $(PROTO_PY_OUT)/__init__.py
	@echo "✓ Python stubs → $(PROTO_PY_OUT)"

proto-go: ## Generate Go gRPC stubs from proto/sentinel.proto
	@echo "→ Generating Go stubs..."
	@mkdir -p $(PROTO_GO_OUT)
	protoc \
		-I proto \
		--go_out=$(PROTO_GO_OUT) \
		--go-grpc_out=$(PROTO_GO_OUT) \
		$(PROTO_SRC)
	@echo "✓ Go stubs → $(PROTO_GO_OUT)"

# ---------------------------------------------------------------------------
# Testing
# ---------------------------------------------------------------------------

test: test-unit test-api ## Run all tests

test-unit: ## Run SentinelRank unit tests
	@echo "→ Running unit tests..."
	pytest ai/tests/test_sentinel_rank.py -v --tb=short

test-api: ## Run FastAPI integration tests
	@echo "→ Running API integration tests..."
	pytest ai/tests/test_api.py -v --tb=short --asyncio-mode=auto

test-coverage: ## Run tests with coverage report
	pytest ai/tests/ -v \
		--cov=ai \
		--cov-report=term-missing \
		--cov-report=html:reports/coverage \
		--asyncio-mode=auto

# ---------------------------------------------------------------------------
# Code quality
# ---------------------------------------------------------------------------

lint: ## Run ruff + mypy
	@echo "→ Linting..."
	ruff check ai/
	mypy ai/ --ignore-missing-imports

fmt: ## Auto-format with ruff
	ruff format ai/

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

download-model: ## Download Mistral-7B-Instruct-v0.2 Q4_K_M (≈4 GB)
	@echo "→ Downloading model to $(MODEL_PATH)..."
	@mkdir -p models
	curl -L --progress-bar "$(MODEL_URL)" -o "$(MODEL_PATH)"
	@echo "✓ Model saved to $(MODEL_PATH)"

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------

build-ai: ## Build the Python AI service Docker image
	docker build -t sentinel-api/ai:2.4.1 \
		-f ai/Dockerfile \
		--build-arg CMAKE_ARGS="-DLLAMA_BLAS=ON" \
		.

build-scanner: ## Build the Go scanner Docker image
	docker build -t sentinel-api/scanner:2.4.1 \
		-f scanner/Dockerfile \
		scanner/

build: build-ai build-scanner ## Build all Docker images

up: ## Start the full stack (AI + UI)
	docker compose up -d ai ui
	@echo "✓ AI backend: http://localhost:8000"
	@echo "✓ Dashboard:  http://localhost:3000"
	@echo "✓ gRPC:       localhost:50051"

down: ## Stop all services
	docker compose down

logs: ## Tail AI service logs
	docker compose logs -f ai

# ---------------------------------------------------------------------------
# Dev
# ---------------------------------------------------------------------------

dev-ai: ## Run AI service locally (no Docker)
	@echo "→ Starting AI service in development mode..."
	uvicorn ai.main:app \
		--host 0.0.0.0 \
		--port 8000 \
		--reload \
		--log-level debug

install: ## Install Python dependencies
	pip install -r ai/requirements.txt

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean: ## Remove generated stubs and build artefacts
	rm -f $(PROTO_PY_OUT)/sentinel_pb2.py $(PROTO_PY_OUT)/sentinel_pb2_grpc.py
	rm -f $(PROTO_GO_OUT)/*.go
	rm -rf reports/coverage __pycache__ .pytest_cache .mypy_cache
	find . -name "*.pyc" -delete

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
