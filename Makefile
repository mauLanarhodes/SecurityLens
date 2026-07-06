GO ?= go
export DATABASE_URL ?= postgres://lens:lens@127.0.0.1:5432/securitylens?sslmode=disable
export REDIS_ADDR ?= 127.0.0.1:6379

.PHONY: help build run seed eval test test-integration check-label-firewall vet web compose-config clean

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-22s %s\n", $$1, $$2}'

build: ## compile all binaries into bin/
	$(GO) build -o bin/server ./cmd/server
	$(GO) build -o bin/seed ./cmd/seed
	$(GO) build -o bin/eval ./cmd/eval

run: build ## start the API + dashboard backend on :8080
	./bin/server

seed: build ## generate + load the synthetic dataset (SEED_LOGS/SEED_DAYS/SEED_SEED)
	./bin/seed

eval: build ## drain the pipeline and score every detector against ground truth
	./bin/eval

test: ## unit tests (detectors, classifier, generator invariants, eval scoring, llm, rulegen)
	$(GO) test ./...

test-integration: ## DB-backed end-to-end detection test (needs Postgres+Redis; uses securitylens_test db)
	$(GO) test -tags=integration -count=1 -v ./internal/integration/

check-label-firewall: ## prove detector code never references ground-truth labels
	@! grep -rn "attack_" internal/detect/ || (echo "FAIL: ground-truth label referenced under internal/detect/"; exit 1)
	@echo "label firewall OK: no attack_ reference under internal/detect/"

vet: ## go vet
	$(GO) vet ./...

web: ## production build of the front end
	cd web && npm install && npm run build

compose-config: ## validate docker-compose.yml (requires docker CLI)
	docker compose config -q && echo "compose config OK"

clean:
	rm -rf bin/
