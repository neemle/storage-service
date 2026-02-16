# SDD-001 Node Volume Role And Backup Wizard

## Scope
Implement the requested admin and user capabilities:
- Admin can manage slave node role from master (`delivery`, `backup`, `volume`) on the fly.
- Admin can configure backup policy using a popup wizard with guided required fields.
- Any user can see max available free space for objects based on volume free space.
- Admin can bind each bucket to selected volume nodes.

## Non-goals
- Replacing chunk-placement algorithm with full RAID-like planner.
- Automatic rebalance/orchestration across nodes.

## Impacted Spec Items
- UC-003 bucket and object lifecycle
- UC-010 backup policy execution and retention
- UC-011 slave node mode control
- BR/WF impacted:
  - WORM/backups and node mode constraints remain enforced.
  - Replica mode changes must remain admin-only.

## Acceptance Criteria
- AC-1: Admin nodes view shows current role/sub-mode from backend state.
- AC-2: Admin can change node sub-mode and UI reflects persisted value after refresh.
- AC-3: Admin can open backup wizard, pass step validations, and create/update policy.
- AC-4: Console bucket list shows max available object space for each bucket.
- AC-5: Admin can bind a bucket to selected volume nodes and persisted mapping is returned.
- AC-6: Bucket free-space calculation uses bound volumes when present, otherwise default volume set.

## Security Acceptance Criteria
- SEC-1: Non-admin callers cannot change node mode or bucket volume bindings.
- SEC-2: Bucket volume bindings reject non-volume nodes and unknown node IDs.
- SEC-3: Validation errors return stable 4xx responses without internal leakage.

## Failure Modes
- Invalid node mode -> `400 invalid replica sub mode`
- Unknown node ID for binding -> `404 node not found`
- Non-volume node in bindings -> `400 node is not eligible as volume`
- Missing auth/admin -> `401/403`

## Test Matrix
- Unit:
  - Admin storage handlers for node mode and bucket volume binding validations.
  - Console bucket listing free-space computation with and without bindings.
- Integration:
  - Admin changes node mode and updates bucket bindings via API.
- Curl:
  - Positive/negative/admin-auth cases for binding + mode update endpoints.
- UI/Playwright:
  - Admin role change flow.
  - Admin backup wizard flow.
  - Admin bucket-volume binding flow.
  - User bucket table shows max available space.
