COMPOSE = docker compose -p css-26c-n05-group-m4-hoan-thien-chu-de-b -f compose/docker-compose.yml
PYTHON ?= python3
PYTEST ?= $(PYTHON) -m pytest

define verify_url
	@attempt=0; \
	until curl -fsS --max-time 2 "$(1)" >/dev/null 2>&1; do \
		attempt=$$((attempt + 1)); \
		if [ $$attempt -ge 30 ]; then \
			echo "ERROR: $(2) chưa sẵn sàng sau 30 lần thử: $(1)" >&2; \
			exit 1; \
		fi; \
		sleep 2; \
	done
endef

.PHONY: preflight up down ps logs build test defend attack verify evidence export-evidence sbom generate-signing-key sign-sbom verify-sbom clean

preflight:
	@set -eu; \
	echo "=== Checking required project files ==="; \
	for file in NHOM.md compose/docker-compose.yml config/keycloak/realm.json ma-nguon/resource-server/Dockerfile ma-nguon/demo-app/Dockerfile; do \
		if [ ! -f "$$file" ]; then \
			echo "ERROR: Required file is missing: $$file" >&2; \
			exit 1; \
		fi; \
	done; \
	echo "Project files: OK"; \
	echo "=== Checking Docker ==="; \
	command -v docker >/dev/null 2>&1 || { echo "ERROR: Docker CLI is required." >&2; exit 1; }; \
	docker compose version; \
	docker info >/dev/null || { echo "ERROR: Docker daemon is unavailable; start Docker Desktop or the Docker service." >&2; exit 1; }; \
	echo "Docker daemon: OK"; \
	echo "=== Checking Python ==="; \
	$(PYTHON) --version; \
	echo "=== Validating Compose configuration ==="; \
	$(COMPOSE) config --quiet; \
	echo "Preflight: OK"

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down -v

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs --tail=100

build:
	$(COMPOSE) build

test:
	@$(COMPOSE) run --rm --build --no-deps \
		-v "$(CURDIR):/workspace:ro" \
		-w /workspace/ma-nguon/resource-server \
		resource-server-1 \
		python -m unittest discover -s tests -v
	@$(COMPOSE) run --rm --build --no-deps \
		-v "$(CURDIR):/workspace:ro" \
		-w /workspace/ma-nguon/demo-app \
		demo-app-1 \
		python -m unittest discover -s tests -v

defend: test
	$(PYTEST) -q tests

attack:
	$(PYTHON) scripts/attack.py

verify: test
	@echo "=== Kiem tra Keycloak ==="
	$(call verify_url,http://127.0.0.1:8080/realms/ecommerce/.well-known/openid-configuration,Keycloak)
	@echo "Keycloak: OK"
	@echo "=== Kiem tra Resource Server 1 ==="
	$(call verify_url,http://127.0.0.1:8001/health,Resource Server 1)
	@echo "Resource Server 1: OK"
	@echo "=== Kiem tra Resource Server 2 ==="
	$(call verify_url,http://127.0.0.1:8002/health,Resource Server 2)
	@echo "Resource Server 2: OK"
	@echo "=== Kiem tra Resource Server 3 ==="
	$(call verify_url,http://127.0.0.1:8003/health,Resource Server 3)
	@echo "Resource Server 3: OK"
	@echo "=== Kiem tra Application 1 ==="
	$(call verify_url,http://127.0.0.1:3001/health,Application 1)
	@echo "Application 1: OK"
	@echo "=== Kiem tra Application 2 ==="
	$(call verify_url,http://127.0.0.1:3002/health,Application 2)
	@echo "Application 2: OK"
	@echo "=== Kiem tra Application 3 ==="
	$(call verify_url,http://127.0.0.1:3003/health,Application 3)
	@echo "Application 3: OK"
	$(MAKE) --no-print-directory attack
	$(MAKE) --no-print-directory export-evidence
	@echo "M3 security evidence: PASS"
	@echo "M2 verification: PASS"

evidence:
	$(MAKE) --no-print-directory export-evidence

export-evidence:
	$(PYTHON) scripts/export_filtered_realm.py
	$(PYTHON) scripts/make_manifest.py

sbom:
	$(PYTHON) scripts/generate_sbom.py

sign-sbom:
	@test -f cosign.key || { echo "ERROR: cosign.key is missing; run 'make generate-signing-key' first." >&2; exit 1; }
	cosign sign-blob --signing-config cosign-signing-config.json --key cosign.key --bundle sbom.cdx.sigstore.json sbom.cdx.json

verify-sbom:
	cosign verify-blob --insecure-ignore-tlog --key cosign.pub --bundle sbom.cdx.sigstore.json sbom.cdx.json

generate-signing-key:
	cosign generate-key-pair

clean:
	$(COMPOSE) down -v --remove-orphans
