# PolicyGuard

A lightweight, policy-as-code evaluation engine for validating deployment requests against configurable YAML-defined rules. Built in Go, designed for platform teams who need to enforce governance on infrastructure deployments without hardcoding checks into CI/CD or admission controllers.

## What It Does

PolicyGuard receives a deployment request (service name, image, resources, labels, capabilities, etc.) and evaluates it against a set of policies defined in YAML. Each policy rule carries a severity — **deny** or **warn** — and the engine returns a structured decision:

| Decision | Meaning |
|---|---|
| `allow` | No violations or warnings |
| `warn` | One or more warning-level rules triggered |
| `deny` | At least one deny-level rule triggered |

### Built-in Rule Types

| Rule | What It Checks |
|---|---|
| `required_labels` | Ensures specified labels are present |
| `forbidden_registry` | Blocks images from disallowed registries |
| `image_regex` | Validates image name format against a regex |
| `max_cpu` | Caps CPU core requests |
| `max_memory` | Caps memory (MiB) requests |
| `min_replicas` | Enforces minimum replica count |
| `forbidden_capabilities` | Blocks specific Linux capabilities |

Rules can be scoped to specific environments (e.g., `production`, `staging`) or applied globally.

## Quick Start

```bash
# Build
make build

# Run (default: port 8080, policies from configs/policies.yaml)
make run

# Or with custom config
policyguard -port 9090 -policy-dir /etc/policies/my-policies.yaml -log-level debug
```

### Docker

```bash
docker build -t policyguard:latest .
docker run -p 8080:8080 policyguard:latest
```

## API

### `POST /v1/evaluate`

Evaluate a deployment request against loaded policies.

**Request:**
```json
{
  "service_name": "web-frontend",
  "environment": "production",
  "image": "registry.example.com/web-frontend:v2.1.0",
  "cpu": 2,
  "memory": 4096,
  "replicas": 3,
  "labels": {
    "app.kubernetes.io/name": "web-frontend",
    "app.kubernetes.io/version": "v2.1.0",
    "team": "platform"
  },
  "owner": "platform-team",
  "capabilities": ["NET_BIND_SERVICE"]
}
```

**Response (200 — allow):**
```json
{
  "decision": "allow",
  "violations": [],
  "warnings": [],
  "explanation": "Deployment request allowed — no policy violations detected.",
  "evidence_refs": []
}
```

**Response (422 — deny):**
```json
{
  "decision": "deny",
  "violations": [
    {
      "rule_type": "required_labels",
      "severity": "deny",
      "description": "Missing required labels: app.kubernetes.io/name, team",
      "detail": "expected labels: [app.kubernetes.io/name app.kubernetes.io/version team]",
      "policy_name": "platform-defaults"
    }
  ],
  "warnings": [],
  "explanation": "Deployment request denied — 1 critical violation(s) found.\n1. required_labels: Missing required labels...",
  "evidence_refs": [
    {
      "policy_name": "platform-defaults",
      "rule_type": "required_labels",
      "message": "required_labels: Every deployment must include standard Kubernetes and team labels"
    }
  ]
}
```

### Health & Readiness

| Endpoint | Description |
|---|---|
| `GET /healthz` | Always returns `200 ok` if the process is running |
| `GET /readyz` | Returns `200 ready` only when policies are loaded; `503` otherwise |
| `GET /metrics` | Prometheus metrics endpoint |

### Configuration

| Flag | Env Var | Default | Description |
|---|---|---|---|
| `-port` | `PORT` | `8080` | HTTP listen port |
| `-policy-dir` | `POLICY_DIR` | `configs/policies.yaml` | Path to policy YAML file |
| `-log-level` | `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |

## How It Works

### Architecture

```
                          ┌─────────────────────┐
                          │   Policy YAML File   │
                          │  (configs/*.yaml)    │
                          └──────────┬──────────┘
                                     │
                          ┌──────────▼──────────┐
                          │     Parser/Loader    │
                          │  ┌────────────────┐  │
                          │  │ ParseFile()    │  │
                          │  │ resolveRule()  │  │
                          │  │ Validate()     │  │
                          │  └────────────────┘  │
                          └──────────┬──────────┘
                                     │  PolicySet[]
                          ┌──────────▼──────────┐
                          │   HTTP Server        │
                          │  ┌────────────────┐  │
              POST /v1/   │  │ /v1/evaluate   │  │
              /evaluate ──►  │ /healthz       │  │
                          │  │ /readyz        │  │
                          │  │ /metrics       │  │
                          │  └────────────────┘  │
                          └──────────┬──────────┘
                                     │  EvaluationResult
                          ┌──────────▼──────────┐
                          │    Policy Evaluator  │
                          │  ┌────────────────┐  │
                          │  │ Evaluate()     │  │
                          │  │ checkRule()    │  │
                          │  │ Decision logic │  │
                          │  └────────────────┘  │
                          └─────────────────────┘
```

### Key Design Decisions

- **Hot reload** — Policies are watched via `fsnotify` with debouncing. Changes are picked up without restart; failed reloads preserve the last known-good state.
- **Graceful degradation** — If the initial policy load fails, the service still starts (serving health endpoints) but reports `not ready` on `/readyz`.
- **Stdlib-first HTTP** — Uses Go 1.22+ `net/http` ServeMux with method-anchored routes (`GET /path`, `POST /path`). No external web framework.
- **Prometheus ready** — `/metrics` exposes a Prometheus handler out of the box.
- **Structured logging** — JSON-formatted logs via `log/slog` with configurable levels.

### Project Structure

```
.
├── cmd/policyguard/
│   └── main.go              # Entrypoint: config, logger, policy loader, server lifecycle
├── internal/
│   ├── api/
│   │   ├── server.go        # HTTP server setup, middleware wiring, lifecycle
│   │   └── handler/
│   │       ├── evaluate.go  # POST /v1/evaluate handler
│   │       └── health.go    # /healthz, /readyz handlers + metrics stubs
│   ├── config/
│   │   └── config.go        # CLI flags + env var configuration
│   ├── log/
│   │   └── log.go           # Structured JSON logger (slog wrapper)
│   ├── middleware/
│   │   └── requestid.go     # X-Request-ID injection middleware
│   └── policy/
│       ├── types.go         # Domain types: rules, severities, decisions, request/result
│       ├── parser.go        # YAML parsing, validation, resolution
│       ├── loader.go        # File-based loading, hot-reload with fsnotify
│       └── evaluator.go     # Rule evaluation logic (one check function per rule type)
├── pkg/errors/
│   └── errors.go            # Sentinel error taxonomy
├── configs/
│   ├── policies.yaml        # Default policy definitions
│   └── testdata/            # Sample JSON requests for testing
├── Dockerfile               # Multi-stage build (golang:1.23-alpine → alpine:3.19)
├── Makefile                 # Build, test, lint, fmt, docker targets
└── .golangci.yml            # golangci-lint configuration
```

## Policy Configuration

Policies are defined in YAML. A policy file contains one or more named policy sets, each with rules scoped to specific environments (or globally).

### Example

```yaml
policies:
  - name: platform-defaults
    environments: []              # empty = all environments
    rules:
      - type: required_labels
        severity: deny
        labels:
          - app.kubernetes.io/name
          - team
        description: "Every deployment must include standard labels"

      - type: forbidden_registry
        severity: deny
        registries:
          - "docker.io/library/"
          - "localhost:"
        description: "No images from Docker Hub library or localhost"

  - name: production-hardening
    environments: ["production"]  # only applies to production
    rules:
      - type: min_replicas
        severity: deny
        value: 2
        description: "Production must have at least 2 replicas"

      - type: forbidden_capabilities
        severity: deny
        capabilities:
          - NET_RAW
          - SYS_ADMIN
        description: "No privileged capabilities in production"
```

### Environment Overrides

Policy sets can include environment-specific rule overrides:

```yaml
policies:
  - name: security-baseline
    environments: []
    rules:
      - type: forbidden_capabilities
        severity: deny
        capabilities: ["SYS_ADMIN", "ALL"]
        description: "SYS_ADMIN and ALL capabilities are forbidden everywhere"
    overrides:
      - environment: staging
        rules:
          - type: max_cpu
            severity: deny
            value: 6
            description: "Staging CPU must not exceed 6 cores"
```

## Development

### Prerequisites

- Go 1.23+
- `golangci-lint` (for `make lint`)
- Docker (optional, for container builds)

### Make Targets

```bash
make          # fmt + vet + lint + build + test (full pipeline)
make build    # Compile to bin/policyguard
make test     # Run tests with race detector
make vet      # go vet ./...
make lint     # golangci-lint run
make fmt      # go fmt ./...
make tidy     # go mod tidy
make test-coverage  # Generate coverage.html report
make clean    # Remove build artifacts
make docker-build   # Build Docker image
make run      # Build and run locally
```

### Adding a New Rule Type

1. **Define the rule type constant** in `internal/policy/types.go`:
   ```go
   RuleTypeMyNewCheck RuleType = "my_new_check"
   ```

2. **Add validation** in `internal/policy/parser.go` (`resolveRule`):
   ```go
   case RuleTypeMyNewCheck:
       if raw.Value <= 0 {
           return Rule{}, fmt.Errorf("my_new_check rule must have a positive value")
       }
   ```

3. **Add the check function** in `internal/policy/evaluator.go`:
   ```go
   func checkMyNewCheck(rule Rule, req EvaluationRequest) (RuleViolation, bool) {
       // Your validation logic here.
       // Return (RuleViolation{}, false) if the rule passes.
       // Return (RuleViolation{...}, true) if it violates.
   }
   ```

4. **Wire it into the dispatcher** in `checkRule()` (`evaluator.go`):
   ```go
   case RuleTypeMyNewCheck:
       return checkMyNewCheck(rule, req)
   ```

5. **Write tests** in `internal/policy/evaluator_test.go`.

6. **Update the YAML schema** — document the new rule in `configs/policies.yaml` as an example.

### Testing

```bash
# All tests
make test

# Coverage report
make test-coverage

# Test a specific package
go test -v ./internal/policy/...
```

### Linting

```bash
make lint
```

Configured linters (`.golangci.yml`): `errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`, `misspell`, `unconvert`, `unparam`.

## License

See `LICENSE`.
