Build a production-grade Go service called `policyguard` that evaluates deployment requests against a configurable policy engine.

Requirements:
- Language: Go 1.23+
- Deliver as a complete repo layout with:
  - `cmd/policyguard`
  - `internal/...`
  - `pkg/...` only if justified
  - `README.md`
  - `Makefile`
  - `Dockerfile`
  - `.golangci.yml`
  - sample config and sample test data
- Expose an HTTP API:
  - `POST /v1/evaluate`
  - `GET /healthz`
  - `GET /readyz`
  - `GET /metrics`
- Input to `/v1/evaluate`:
  - JSON deployment request containing service name, environment, image, cpu, memory, replicas, labels, annotations, owner, and requested capabilities
- Output:
  - decision: `allow`, `deny`, or `warn`
  - list of violated rules
  - list of warnings
  - normalized explanation suitable for humans
  - machine-readable evidence references

Policy engine behavior:
- Policies are loaded from YAML files at startup
- Support:
  - required labels
  - forbidden registries
  - max cpu/memory per environment
  - forbidden Linux capabilities
  - minimum replicas for production
  - regex validation for image naming
- Support rule severity:
  - `deny`
  - `warn`
- Support policy overrides by environment
- Support hot reload when policy files change, without restarting the service
- Validation must fail safely if policy files are invalid

Non-functional requirements:
- Strong typing and clean package boundaries
- Context propagation and graceful shutdown
- Structured logging
- Prometheus metrics
- Unit tests for parser, evaluator, and handlers
- Table-driven tests
- At least one fuzz test for untrusted input handling
- Clear error taxonomy
- No global mutable state unless justified
- Concurrency-safe hot reload
- No panics on malformed input
- Lint-clean and fmt-clean

Implementation constraints:
- Do not use a full framework
- Prefer standard library where reasonable
- Explain tradeoffs before coding
- Create a short implementation plan first
- Then generate the code incrementally
- After coding, run through a self-review:
  - identify design weakness
  - identify race-condition risks
  - identify API edge cases
  - identify config parsing risks
  - propose improvements
- Then apply the improvements
- Then produce final output:
  1. repo tree
  2. key files
  3. tests
  4. sample curl requests
  5. explanation of design decisions
  6. known limitations

Quality bar:
- Act like a senior engineer doing work that will be reviewed by a platform team
- Do not stop at "it compiles"
- If lint/test issues would remain, fix them
- If you introduce a placeholder or TODO, explain why it exists and what would be needed to finish it
- Prefer correctness, maintainability, and observability over minimal code