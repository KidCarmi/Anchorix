SHELL := /bin/bash

# ---- Variables ----
BACKEND_DIR  := backend
FRONTEND_DIR := frontend
AGENT_DIR    := agent/windows
COMPOSE      := docker compose

.PHONY: help dev down logs ps backend-build backend-run backend-test backend-lint \
        frontend-install frontend-dev frontend-build frontend-test frontend-lint \
        agent-build migrate clean

help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---- Compose ----
dev: ## Bring up the full Docker Compose stack with rebuild.
	$(COMPOSE) up --build

down: ## Tear down the Compose stack.
	$(COMPOSE) down

logs: ## Tail logs from all Compose services.
	$(COMPOSE) logs -f --tail=200

ps: ## Show Compose service status.
	$(COMPOSE) ps

# ---- Backend ----
backend-build: ## Build the control plane binary.
	cd $(BACKEND_DIR) && go build -o bin/anchorix ./cmd/anchorix

backend-run: ## Run the control plane locally.
	cd $(BACKEND_DIR) && go run ./cmd/anchorix

backend-test: ## Run backend tests.
	cd $(BACKEND_DIR) && go test ./...

backend-lint: ## Run go vet (and golangci-lint if available).
	cd $(BACKEND_DIR) && go vet ./...
	@command -v golangci-lint >/dev/null && cd $(BACKEND_DIR) && golangci-lint run || echo "golangci-lint not installed; skipping"

migrate: ## Apply pending DB migrations.
	cd $(BACKEND_DIR) && go run ./cmd/anchorix migrate up

# ---- Frontend ----
frontend-install: ## Install frontend dependencies.
	cd $(FRONTEND_DIR) && npm install

frontend-dev: ## Run the frontend dev server.
	cd $(FRONTEND_DIR) && npm run dev

frontend-build: ## Build the frontend for production.
	cd $(FRONTEND_DIR) && npm run build

frontend-test: ## Run frontend tests.
	cd $(FRONTEND_DIR) && npm test

frontend-lint: ## Run frontend lint + typecheck.
	cd $(FRONTEND_DIR) && npm run lint && npm run typecheck

# ---- Windows agent ----
agent-build: ## Cross-compile the Windows agent (amd64).
	cd $(AGENT_DIR) && GOOS=windows GOARCH=amd64 go build -o ../../dist/anchorix-agent.exe ./cmd/anchorix-agent

# ---- Misc ----
clean: ## Remove build artifacts.
	rm -rf $(BACKEND_DIR)/bin $(BACKEND_DIR)/tmp \
	       $(FRONTEND_DIR)/dist $(FRONTEND_DIR)/.vite \
	       $(AGENT_DIR)/bin $(AGENT_DIR)/tmp \
	       dist/
