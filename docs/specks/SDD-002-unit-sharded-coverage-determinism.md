# SDD-002 Unit Sharded Coverage Determinism

## Scope
- Stabilize backend unit sharded execution so coverage is computed from the exact binary and profiles created in
  the current run.
- Keep coverage thresholds at 100% lines/functions/regions and fix only sharded orchestration behavior.

## Non-goals
- Changing coverage thresholds.
- Reducing test scope or disabling existing unit tests.
- Changing CI workflow structure outside current sharded unit script behavior.

## Impacted Spec Items
- UC-006 CI/CD delivery contract.
- BR/WF impacted:
  - Fail-fast stage behavior remains unchanged.
  - Unit coverage gate remains strict and deterministic.

## Acceptance Criteria
- AC-1: Sharded unit run builds and executes tests using the binary produced in the same list/build step.
- AC-2: Sharded unit run does not reuse stale llvm-cov target/build artifacts from prior runs.
- AC-3: Sharded unit run still enforces configured coverage fail-under gates for lines/functions/regions.
- AC-4: Per-shard profile output uses per-process naming so concurrent/subprocess profile writes cannot overwrite
  each other.
- AC-5: Coverage report is generated from merged shard profiles against the exact shard-run test binary, without
  rebuilding a new binary during report.

## Security Acceptance Criteria
- SEC-1: Shard test argument expansion only consumes generated internal test names and does not execute arbitrary
  shell content.
- SEC-2: Error handling preserves fail-fast behavior when test discovery or binary detection fails.

## Failure Modes
- No tests discovered from list output -> fail with explicit error.
- Test binary path cannot be resolved -> fail with explicit error.
- Any shard exits non-zero -> fail before report generation.
- Profile output clobbered by concurrent writes -> prevented via `%p/%m` profile filename placeholders.
- Report binary drift from rebuild -> prevented by `llvm-profdata` + `llvm-cov` over the previously discovered
  test binary.
- Coverage under threshold -> fail with existing fail-under gates.

## Test Matrix
- Unit:
  - Run `scripts/unit-tests-sharded.sh` with shard count > 1 and verify successful shard completion.
  - Verify coverage report generation still applies fail-under thresholds.
- Integration:
  - Not applicable (script-only change).
- Curl/UI:
  - Not applicable.
