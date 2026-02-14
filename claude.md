# AI Agents Rules — Monorepo (Backend + Frontend)

STRICT / NON-NEGOTIABLE rules for all AI agents in this repo.

Project-specific onboarding and operation guide:
- `docs/ai-agent-guide.md`

---

## 0) Scope & Applicability

Repo may contain:
- Backend API only (NestJS or ASP.NET Core/.NET or existing backend)
- Frontend only (React/Angular/Vue)
- Fullstack monorepo

Apply **only** relevant rules/suites to what exists, but preserve **fail-fast order**.

---

## 1) Global Rules (Always)

### 1.1 Type safety

**TypeScript (if TS exists)**
- NEVER use `any`
- NEVER use type casts (`as`, `<T>`) to bypass correctness
- Prefer explicit interfaces, generics, discriminated unions, utility types, exhaustive `never` checks

**C#/.NET (if C# exists)**
- Prefer explicit types when it improves readability
- Avoid `dynamic` unless unavoidable and justified by existing architecture
- No unsafe casts to bypass correctness (`(T)obj` without checking); use `is`/pattern matching/`TryParse`
- Respect nullable reference types; do not silence warnings without reason
- No reflection-based hacks to bypass typing/validation

**Violation = failed task.**

---

### 1.2 Code style & maintainability (hard limits)

Applies to all newly written/modified code.

- Max line length: **120 chars**
- Max method/function length: **30 non-empty, non-comment lines**
- Max class length: **500 non-empty, non-comment lines**

Counting:
- Exclude empty + comment-only lines
- Include executable/semantic lines; braces/signatures if on their own lines

If touched code already violates limits:
- Do not refactor unrelated code purely for style
- Prefer minimal extraction (helpers/private methods/smaller types) with identical behavior unless requested change
- If requested change cannot be done without exceeding limits: request explicit approval

---

### 1.3 Code quality

- Provide full working code (no placeholders)
- No TODOs, commented-out logic, or dead code
- Follow existing architecture/conventions
- Keep changes minimal/scope-limited
- Prefer readable over clever
- Do not reduce security, validation, or observability

---

### 1.4 Documentation doctrine: `functional.md` is the business truth

Repo MUST contain root-level `functional.md` describing:
- how the project works **and why it works**
- business rules/invariants
- use cases (happy paths + failure modes)

**Doc-first workflow for ANY requested modification (feature/bugfix/behavior change/refactor changing outcomes):**
1) resolve business-level conflicts in `functional.md`
2) update impacted use cases + acceptance criteria in `functional.md`
3) only then implement code + tests to match

Agents MUST NOT implement behavior contradicting `functional.md`.
If `README.md` and `functional.md` disagree, fix to be consistent as part of the task.

---

### 1.5 Forbidden actions

- Breaking API changes without explicit approval
- Changing env vars/secrets without explicit approval
- Modifying CI/CD unless explicitly requested
- Skipping tests, lowering coverage thresholds, disabling reporting
- Ignoring failing tests
- Introducing flaky tests

---

## 2) Testing & Quality Doctrine (Critical)

### 2.1 Test change policy
- Adding tests is always allowed and often required (coverage/edge cases/bug reproduction/regression prevention)
- Modifying/removing existing tests is FORBIDDEN without explicit user approval  
  (until approved: add new tests reflecting new behavior where possible)

### 2.2 Container-first execution
- ALL tests must run in Docker containers (local + CI)
- No host dependencies/manual setup
- Required infra (DB/cache/queue/object storage) must be dockerized (usually via `docker-compose.yml`)

### 2.3 Ephemeral DB rule (for any DB-backed suite)
For integration/curl/UI/runtime/production tests using a real DB:
- DB starts empty every run
- No persisted volumes (no bind mounts, no reused named volumes)
- Must include readiness gate (healthcheck or explicit wait)
- Retries must be bounded (max attempts + max wait)
- Migrations/seeds run only after readiness confirmed

(Unit tests should not need DB; if they do, they are treated as DB-backed and must follow this rule.)

---

## 3) Test Taxonomy & Required Stages

### Stage definitions
1) **Unit**: method-level, isolated, no network/real infra
2) **Integration**: class boundary + real internal deps; if runtime uses DB → real DB container
3) **Curl (runtime/dev image)**: start service container(s), hit with real `curl`, assert status + body
4) **Base UI (Playwright)**: short journeys/smoke flows
5) **UI (Playwright + dockerized headless Chromium)**: long journeys, real interactivity
6) **Runtime (production API image via curl)**: curl against shipped/minified API image
7) **Production (final fullstack images)**: backend + frontend final images + dockerized Chromium UI tests

### Fail-fast order (mandatory)
1. Unit
2. Integration
3. Curl (runtime/dev)
4. Base UI (Playwright)
5. UI (Playwright headless Chromium)
6. Runtime (curl on production API image)
7. Production (final images + UI)

CI stops at first failing stage; downstream stages must not run after failure.

---

## 4) Coverage Requirements

### 4.1 Code coverage (Unit + Integration only)
Measured across lines/expressions/functions:
- Unit: **100%**
- Integration: **100%**
  No gaming with meaningless assertions.

### 4.2 API coverage (Stage 6: curl against production API image)
**Separate from code coverage.**

**API coverage definition:** a route is covered only if a curl test:
- calls the route (method + path pattern),
- asserts status code,
- asserts response body shape/content,
- verifies primary business outcome.

**Requirement:** Stage 6 MUST achieve **100% API coverage** of all publicly exposed routes.

Per route, cover applicable outcomes from `functional.md`:
- success
- validation errors (400/422) when rules exist
- auth failures (401/403) when auth exists
- not-found (404) when lookups exist
- conflicts (409) when uniqueness/concurrency exists

Route inventory source of truth (priority):
1) generated OpenAPI/Swagger (if present)
2) `functional.md` documented API surface/use cases
3) explicit route inventory file (only if no OpenAPI)

If it exists in OpenAPI, it MUST be covered.

---

## 5) UI Test Coverage Doctrine (Playwright)

### 5.1 Mapping to `functional.md` (mandatory)
- Every Playwright test must map to at least one use case (UC-###)
- Test titles MUST include UC id(s), e.g. `test('[UC-012] ...', ...)`

### 5.2 Journeys from short → long (mandatory)
Based on what `functional.md` describes/permits:
- **Base UI** must cover shortest viable happy paths for primary user goals
- **UI suite** must cover longer multi-step success flows for primary user goals,
  plus meaningful alternates/failure flows where UI is responsible (validation/auth/empty/conflict messaging)

### 5.3 Real user interaction (mandatory)
- clicks/scrolls/typing/form submits
- prove elements are interactable (not just present/visible)
- dockerized headless Chromium (no host browser dependency)

### 5.4 Reports & artifacts (mandatory)
Playwright runs MUST produce debuggable outputs:
- HTML report enabled for every run
- on failures: **screenshots + videos** MUST be captured
- traces strongly recommended (at least on failure or retries)
- artifacts must be written to predictable directories (e.g., `playwright-report/`, `test-results/`)
- CI should publish artifacts when possible (do not change CI/CD unless explicitly requested)

---

## 6) Agent Roles (apply only when relevant)

### Backend Engineer (Generic)
Owns: routes/controllers/handlers, services, data access/migrations, validation/auth boundaries,
unit + integration + curl + runtime(production curl) tests.
Must: validate all external input, use explicit DTOs/contracts, keep API stable unless approved.
Must not: change frontend unless instructed; weaken auth/validation; make breaking API changes without approval.

### Backend Engineer (NestJS)
Must: modules/controllers/providers; pipes/guards/interceptors; class-validator/class-transformer where applicable;
integration tests with real modules + real DB container when runtime uses DB.
Constraints: global prefix `/api`, Swagger `/api/docs`, Nest serves static content if frontend build exists.

### Backend Engineer (ASP.NET Core/.NET)
Must: controllers/minimal APIs, middleware/filters, DI services, validation boundaries, EF Core (if used),
integration tests with test host + real DB container when runtime uses DB.
Constraints: do not change route prefixes/Swagger paths unless instructed; production tests must serve minified frontend
if backend serves frontend; all runtime/prod tests containerized (no host IIS).

### Frontend Engineer
Owns: components/pages, typed API client, state/forms/routing, unit/component tests,
Playwright base UI + UI suites.
Must: strict TS, no `any`/unsafe casts, handle errors/empty states, tests must do real interactions.
Must not: change backend APIs unless instructed; add new frameworks/state libs without approval.

### Integration Tester
Must: write valuable integration tests, reproduce bugs (fails before, passes after), no snapshot-only,
real infra when runtime uses it (especially DB).

### UI/E2E Tester (Playwright)
Must: short→long journeys mapped to UC-###, dockerized Chromium, interactable assertions,
reports with screenshots+videos (and traces recommended).

### Runtime/Release Tester
Must: Stage 6 curl tests against production API image with 100% API coverage,
Stage 7 final images validation with dockerized infra + Chromium.

---

## 7) Tool Permissions

Allowed:
- filesystem read/write
- node/npm/yarn/pnpm
- dotnet CLI when .NET exists
- unit/integration test runners
- Playwright
- docker
- git (read-only)

Forbidden:
- direct DB mutation outside migrations/seeds used by the app
- network access outside test scope
- disabling coverage or reporting

---

## 8) Conflict Resolution Order

1) System message
2) User instruction
3) `agents.md`
4) `functional.md`
5) `README.md`

If truly ambiguous — ask before acting.

---

## 9) Architecture & Infrastructure Constraints

General:
- root `docker-compose.yml` must boot required infra
- no host installs
- seeds/migrations/tests must run in the same docker-compose service as the API (when API exists) for env parity

---

## 10) “Done” Deliverables

Repo is “done” only if it contains:
- root `docker-compose.yml`
- `.env` with safe local defaults (no real secrets)
- `README.md` (run backend/frontend/both; run tests in fail-fast order; config/options)
- root `functional.md` (how/why it works + business rules + use cases)
- Playwright reporting configured to produce:
    - HTML report
    - screenshots + videos on failures (and traces recommended)
