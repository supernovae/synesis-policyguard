# PolicyGuard — Implementation Plan

**Status:** Draft · **Created:** 2026-04-05

---

## Goals

Build a production-grade Go service called `policyguard` that evaluates deployment
requests against a configurable policy engine loaded from YAML.

---

## Repo Layout

```
policyguard/
├── cmd/policyguard/
│   └── main.go                 # Entrypoint: wire dependencies, start server, signal handling
├── internal/
│   ├── api/
│   │   └── server.go           # HTTP server lifecycle, route registration
│   ├── api/handler/
│   │   ├── evaluate.go         # POST /v1/evaluate
│   │   ├── health.go           # GET /healthz, /readyz
│   │   └── handler_test.go     # Table-driven + integration tests
│   ├── policy/
│   │   ├── types.go            # Domain types (Policy, Rule, EvaluationRequest, Result, etc.)
│   │   ├── parser.go           # YAML → typed Policy struct
│   │   ├── parser_test.go      # Table-driven + fuzz tests
│   │   ├── evaluator.go        # Apply policies to a request → Result
│   │   ├── evaluator_test.go   # Table-driven + fuzz tests
│   │   └── loader.go           # File watch + hot reload with atomic swap (RWMutex)
│   ├── config/
│   │   └── config.go           # Server config (port, log level, policy file path)
│   └── log/
│       └── log.go              # Structured logging wrapper (slog)
├── pkg/errors/
│   └── errors.go               # Sentinel errors + classification helpers
├── configs/
│   ├── policies.yaml           # Sample policy file
│   └── testdata/
│       ├── valid_request.json
│       ├── denied_request.json
│       └── policies_invalid.yaml
├── README.md
├── Makefile
├── Dockerfile
├── .golangci.yml
├── go.mod
└── go.sum
```

---

## Design Decisions

### 1. Standard Library HTTP (No Framework)

**stdhttp** `ServeMux` (Go 1.22+) supports method-anchored routing like `"POST /v1/evaluate"`.
No gorilla/mux, chi, or gin needed.

### 2. Policy Hot Reload via fsnotify + RWMutex

The `loader` watches policy files with `fsnotify` (the canonical third-party dependency).
On modification event it re-parses and atomically swaps the in-memory policy slice under
an `sync.RWMutex`. Reads on `/v1/evaluate` use `RLock()`, reload uses `Lock()`.
If reload fails the old policies remain — safe fallback.

### 3. No Global Mutable State

- `Handler` receives `*policy.Loader` via its struct field (DI)
- `Loader` owns a `*policySet` behind `RWMutex`
- Server, handler, all injected

### 4. Error Taxonomy (`pkg/errors`)

| Sentinel Error | Meaning |
|-|-|
| `ErrParseFailure` | Bad YAML / malformed policy |
| `ErrEvaluationDenied` | At least one deny-level rule violated |
| `ErrInternalError` | Unexpected server-side issue |

### 5. Prom Metrics

Four metrics exposed via `promhttp`:
- `policyguard_evaluations_total` — counter by result (`allow`/`deny`/`warn`)
- `policyguard_evaluation_duration_seconds` — histogram
- `policyguard_policy_reload_total` — counter (success/failed)
- `policyguard_policy_version` — gauge = Unix mtime of loaded file

### 6. Go Logging

Use `log/slog` (stdlib since 1.21) with JSON handler for production.

---

## Implementation Steps

### Step 1: Bootstrap — go.mod, Makefile, .golangci.yml, Dockerfile
Create module, tooling scaffolding, build/run targets.

### Step 2: Domain Types (`internal/policy/types.go`, `pkg/errors/errors.go`)
Define `EvaluationRequest`, `Policy`, `Rule`, `RuleResult`, `EvaluationResult`,
severity constants, decision constants. Sentinel errors.

### Step 3: Policy Parser (`internal/policy/parser.go` + tests)
Unmarshal YAML → `Policy`. Validate required fields. Table-driven tests.
Fuzz test for malformed YAML.

### Step 4: Policy Evaluator (`internal/policy/evaluator.go` + tests)
Evaluate a request against a policy list. Check each rule type:
required labels, forbidden registries, max CPU, max memory, forbidden
capabilities, min replicas, regex image validation. Table-driven tests.
Fuzz test for malformed JSON request.

### Step 5: Policy Loader with Hot Reload (`internal/policy/loader.go`)
RWMutex-wrapped atomic swap. fsnotify file watcher. Graceful error
handling on bad reload — keeps last valid policies.

### Step 6: Config (`internal/config/config.go`)
Struct for server port, log level, policy file path. Env + flag support.

### Step 7: Structured Logging (`internal/log/log.go`)
slog wrapper with level and JSON format.

### Step 8: HTTP Server + Handlers (`internal/api/server.go`, `internal/api/handler/`)
`POST /v1/evaluate` — decode request, evaluate, return structured response.
`GET /healthz` — always 200.
`GET /readyz` — 200 once policies loaded successfully.
`GET /metrics` — promhttp handler.
Request ID middleware, request logging middleware.

### Step 9: Main (`cmd/policyguard/main.go`)
Wire everything. Signal handler for graceful shutdown. Context
propagation throughout.

### Step 10: Sample Config, Test Data, README
Write sample `policies.yaml`, JSON test payloads, documentation.

### Step 11: Tests, Lint, Self-Review
Run `go test -v -race ./...`, `go vet`, `golangci-lint`, fix issues.
Self-review across design/races/edge cases. Iterate fixes.

---

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| fsnotify duplicate events on some platforms | Debounce with 200ms timer |
| Concurrent reload during active evaluation | RWMutex isolates; evaluation reads, reload writes |
| Malformed policy file during reload | Re-parse fully before swap; on failure, log + keep old |
| YAML library as only non-stdlib dep | Acceptable; `gopkg.in/yaml.v3` is canonical |
| CPU/memory as string vs float | Define as `float64` (CPU cores, memory MiB) in JSON, convert at YAML |
