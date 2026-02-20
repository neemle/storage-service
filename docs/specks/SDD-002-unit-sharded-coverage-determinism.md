# SDD-002 Unit Sharded Coverage Determinism

## Scope
- Stabilize backend unit sharded execution so coverage is computed from the exact binary and profiles created in
  the current run.
- Keep coverage thresholds at 100% lines/functions/regions and fix only sharded orchestration behavior.
- Ensure `api/portal.rs` router embedded fallback path is explicitly exercised in unit tests so coverage remains
  deterministic across CI runs.
- Eliminate sharded-run nondeterminism caused by repeated cluster join token hashes selecting stale consumed rows.

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
- AC-6: Unit tests explicitly execute the router embedded fallback path in `api/portal.rs` and keep that path at
  100% function/line/region coverage.
- AC-7: Sharded unit script executes the full `api::portal::tests::*` list in a dedicated post-shard pass so merged
  coverage always includes portal-only paths regardless of shard assignment variance.
- AC-8: Test discovery parsing strips ANSI control sequences and carriage returns before extracting test names and
  test binary path.
- AC-9: Dedicated post-shard fallback probe must prove the fallback test executed and emitted a profile file; silent
  zero-test probe runs are treated as failures.
- AC-10: Portal router uses a named fallback handler instead of an inline closure so fallback coverage is attributed
  to deterministic, directly testable code paths.
- AC-11: Post-shard portal pass executes each discovered `api::portal::tests::*` test name one-by-one with
  `--exact` and validates every expected test appears as `... ok` in the pass log.
- AC-12: Portal helper functions use `#[cfg_attr(test, inline(never))]` so test/coverage builds cannot lose
  deterministic function attribution due inlining decisions.
- AC-13: Join token consumption must lock/select only currently valid (unused, unexpired) rows so repeated token
  hashes from prior tests cannot produce nondeterministic `401` responses in sharded runs.
- AC-14: Portal handler coverage test for `embedded_ui` must execute through an explicit Tokio runtime in a
  plain `#[test]` to avoid macro-wrapper attribution variance in CI coverage builds.

## Security Acceptance Criteria
- SEC-1: Shard test argument expansion only consumes generated internal test names and does not execute arbitrary
  shell content.
- SEC-2: Error handling preserves fail-fast behavior when test discovery or binary detection fails.

## Failure Modes
- No tests discovered from list output -> fail with explicit error.
- Test binary path cannot be resolved -> fail with explicit error.
- Any shard exits non-zero -> fail before report generation.
- Control characters in `--list` output break test extraction -> prevented by normalized parsing before extraction.
- Profile output clobbered by concurrent writes -> prevented via `%p/%m` profile filename placeholders.
- Report binary drift from rebuild -> prevented by `llvm-profdata` + `llvm-cov` over the previously discovered
  test binary.
- Router embedded fallback closure not executed -> prevented by dedicated router-fallback unit test.
- Router fallback path omitted due shard execution variance -> prevented by dedicated post-shard portal test pass.
- Dedicated portal pass matches zero tests -> prevented by required `portal-tests.list` generation, pass-log
  assertion, and portal profile output check.
- Inline fallback closure counted as a separate uncovered function in some runs -> prevented by using a named fallback
  handler plus direct handler unit coverage.
- Multi-filter test invocation ambiguity causes partial/zero portal execution -> prevented by per-test exact execution
  and explicit expected-vs-seen portal test verification.
- Compiler inlining in test binaries causes occasional function-attribution misses -> prevented by
  `#[cfg_attr(test, inline(never))]` on portal helper functions.
- `consume_join_token` chooses an arbitrary stale row for duplicate token hashes -> prevented by filtering/locking
  only unused + unexpired rows before marking token as used.
- Tokio test macro wrapper attribution for `embedded_ui` helper path can fluctuate in instrumented builds ->
  prevented by explicit-runtime plain test for direct `embedded_ui` execution.
- Coverage under threshold -> fail with existing fail-under gates.

## Test Matrix
- Unit:
  - Run `scripts/unit-tests-sharded.sh` with shard count > 1 and verify successful shard completion.
  - Verify coverage report generation still applies fail-under thresholds.
  - Verify `api/portal.rs` row reports 100% for regions/functions/lines.
  - Verify post-shard portal pass log exists at `scripts/tmp/unit-shards/portal-fallback.log`.
  - Verify normalized test-list output exists at `scripts/tmp/unit-shards/list-output-clean.log`.
  - Verify portal pass uses `scripts/tmp/unit-shards/portal-tests.list` and reports `test result: ok.`.
  - Verify named fallback handler test `embedded_ui_handler_uses_embedded_dir` passes and contributes coverage.
  - Verify every portal test listed in `portal-tests.list` appears in `portal-fallback.log` as `test ... ok`.
  - Verify `api/portal.rs` helper functions are annotated with `#[cfg_attr(test, inline(never))]`.
  - Verify duplicate `join_tokens.token_hash` rows still consume the latest valid unused row and do not return `401`
    when a valid row exists.
  - Verify `embedded_ui_handler_uses_embedded_dir` executes as a plain `#[test]` using explicit Tokio runtime and
    contributes deterministic handler coverage.
- Integration:
  - Not applicable (script-only change).
- Curl/UI:
  - Not applicable.
