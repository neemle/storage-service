# SDD-003 Unit Test Runner Image Cache

## Scope
- Speed up Stage 1 backend unit tests by caching the test-runner Docker image layers in GitHub Actions.
- Ensure the cached image is loaded locally in the job and reused by `scripts/unit-tests.sh`.
- Keep the cached image deterministic by pinning Rust/cargo-llvm-cov versions and forcing base image refresh.
- Keep existing unit test behavior, coverage thresholds, and fail-fast stage order unchanged.

## Non-goals
- Changing unit test logic or coverage gates.
- Changing integration/curl/ui/prod stage behavior.
- Publishing the test-runner image to external registries.

## Impacted Spec Items
- UC-006 CI/CD delivery contract.
- BR/WF impacted:
  - Fail-fast stage sequencing remains unchanged.
  - Dockerized test execution remains unchanged.

## Acceptance Criteria
- AC-1: Stage 1 unit job configures Docker Buildx before backend unit execution.
- AC-2: Stage 1 unit job builds `deploy/test-runner.Dockerfile` with GitHub Actions layer cache
  (`cache-from/cache-to`).
- AC-3: Stage 1 unit job loads the built image into local Docker daemon with tag
  `nss-test-runner:ci-cached`.
- AC-4: Backend unit test step uses `NSS_TEST_IMAGE=nss-test-runner:ci-cached` so
  `scripts/unit-tests.sh` reuses the prebuilt image.
- AC-5: Cache write failures must not fail the job (cache is optimization, not correctness gate).
- AC-6: Stage 1 image build forces pulling the pinned base image (`pull: true`) so stale cached bases do not
  lock old Rust patch versions.
- AC-7: `deploy/test-runner.Dockerfile` pins Rust and `cargo-llvm-cov` versions to eliminate toolchain drift
  between local and CI coverage execution.

## Security Acceptance Criteria
- SEC-1: Test runner image build source remains repository-controlled (`deploy/test-runner.Dockerfile`)
  and does not introduce external mutable Dockerfile references.
- SEC-2: No secrets are added to Docker build args, image tags, or cache configuration.

## Failure Modes
- Cache miss on first run -> image still builds successfully and proceeds with tests.
- Cache export unavailable (permission/runtime issue) -> step continues because cache write is non-fatal.
- Image not loaded locally -> unit script falls back to existing `ensure_test_image` build behavior.
- Cached layers continue using outdated Rust patch/tooling -> prevented by pinned versions and `pull: true`
  during image build.

## Test Matrix
- Unit:
  - Run CI Stage 1 and verify Buildx image cache step completes before backend unit tests.
  - Verify backend unit step runs with `NSS_TEST_IMAGE=nss-test-runner:ci-cached`.
  - Verify Stage 1 still enforces unit coverage thresholds.
- Integration:
  - Not applicable.
- Curl/UI:
  - Not applicable.
