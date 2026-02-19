# SDD-004 Stage1 Unit Diagnostics Bundle Reliability

## Scope
- Ensure Stage 1 backend unit failures always produce uploadable diagnostics artifacts.
- Replace oversized/raw artifact upload paths with a compact prepared diagnostics bundle.
- Preserve existing Stage 1 fail-fast behavior and unit coverage enforcement.

## Non-goals
- Changing backend unit test logic or coverage thresholds.
- Changing downstream stage execution order.

## Impacted Spec Items
- UC-006 CI/CD delivery contract.
- BR/WF impacted:
  - Fail-fast stage sequencing remains unchanged.
  - Dockerized test execution remains unchanged.

## Acceptance Criteria
- AC-1: When backend unit tests fail, CI prepares a diagnostics directory under
  `.artifacts/backend-unit-diagnostics`.
- AC-2: Diagnostics bundle includes shard/unit script logs when available (`scripts/tmp/unit-shards`).
- AC-3: Diagnostics bundle includes Docker compose state and recent service logs for test dependencies.
- AC-4: Artifact upload step targets the prepared diagnostics directory only.
- AC-5: Missing optional diagnostics sources do not fail preparation step.

## Security Acceptance Criteria
- SEC-1: Diagnostics bundle must not include repository secrets files or environment dumps containing secrets.
- SEC-2: Docker logs collected are limited to service logs relevant to Stage 1 (`postgres`, `redis`, `rabbitmq`).

## Failure Modes
- Raw artifact upload includes huge build trees and fails zip creation -> prevented by uploading compact bundle only.
- Unit script fails before writing shard logs -> preparation still uploads compose status and CI metadata.
- One diagnostics command fails -> preparation continues via tolerant collection commands.

## Test Matrix
- Unit:
  - Trigger a Stage 1 backend unit failure and verify `backend-unit-diagnostics` artifact exists.
  - Verify artifact contains `meta.txt`, compose diagnostics, and shard logs when present.
  - Verify upload step succeeds even when `target/llvm-cov-*` directories are large.
- Integration:
  - Not applicable.
- Curl/UI:
  - Not applicable.
