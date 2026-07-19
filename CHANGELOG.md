# Changelog - BotOps Manager

Asset metadata: ID `BOTOPS-CHANGELOG`; class `documentation`; role `release-history`; status `current`; sensitivity `project-internal`; tags `botops-manager, changelog, version-history, asset-metadata`.

## v1.13.0 - 2026-07-18 10:38 CDT

Research-driven structured-health release aligned with the v2.16.5 asset-metadata baseline. v1.12.0 remains the rollback baseline.

### Added
- Optional local `botops_health_v1` contract auto-detection at six bounded paths, with no service, network endpoint, installer, or third-party dependency.
- Distinct startup, readiness, liveness, degraded, stopping, failed, and progress context.
- Contract validation for exact schema, allowed states, timezone-aware timestamps, booleans, bounded sequences, PID, process-start epoch, regular-file/path containment, symlink rejection, and configurable 64 KiB default size cap.
- Optional PID and process-creation identity binding. A mismatch cannot become authoritative and automatically falls back to other reliable evidence.
- Dashboard/status/OpenMetrics/diagnostic/omission-ledger fields for contract state, live/ready flags, PID match, heartbeat/progress sequences, message, and validation errors.
- Seven focused regression tests covering selection, state mapping, not-ready handling, identity mismatch fallback, malformed fallback, embedded time skew, and oversized rejection.

### Changed
- Advanced config schema to v17 with `health_contract_max_bytes`; registry/runtime/health schemas remain `2 / 1 / 1`.
- Structured contracts rank above automatically inferred logs only while valid and within the existing bounded freshness model. Manual heartbeat selection remains operator-authoritative.
- Embedded contract time is checked for skew and consistency, but file mtime remains the freshness clock.
- Self-test, runbook, transfer, known-good state, deep-check report, batch ledger, launcher title, and manifests were synchronized to v1.13.0.

### Preserved
- Existing log-based evidence remains zero-configuration fallback for every bot.
- No health evidence can start, stop, restart, adopt, or force-stop a process.
- All v1.12.0 launcher safety, process identity, report-only export, privacy/redaction, Norton, metadata, portability, and Export20 boundaries remain intact.

### Verified
- Warning-strict compile/import: PASS.
- Regression and safety tests: PASS, 111/111.
- Structured-contract tests: PASS, 7/7.
- Synthetic status/self-test/export, asset reconciliation, static scans, ZIP integrity, relocation, and deterministic rebuild: PASS.

### External validation still required
- Real Windows process-control testing, real bot contract publication, exact-final-artifact Norton-on testing, and Drive metadata mirroring were not available in the build environment.

### Rollback
- Restore v1.12.0 and its pre-v17 config backup, or let v1.12.0 generate fresh config. Preserve runtime and diagnostic evidence first.

## v1.12.0 - 2026-07-13 13:12 CDT

Compatible metadata-and-diagnostic integrity release aligned to the checksum-verified ChatGPT New Thread Parameters v2.16.5 Asset Metadata package. v1.11.1 remains the rollback baseline.

### Added
- Canonical asset manifest schema `botops_asset_manifest_v1` with stable IDs, titles, roles, formats, project/version/status, sensitivity, source-of-truth flags, controlled tags/aliases, lineage, timestamps, sizes, and SHA256 values for every retained package file.
- Read-only source asset metadata reconciliation in preflight and diagnostic export. It reports missing records, stale sizes/hashes, duplicate IDs/paths, header gaps, unsupported fields, and release-asset conflicts.
- Manifest-aware source inventory so diagnostics map packaged files to stable asset IDs, roles, lifecycle status, sensitivity, size, and current hash.
- Versioned diagnostic filenames, embedded ZIP-comment metadata, run-specific diagnostic asset IDs, companion checksum-asset identity, and adjacent SHA256 metadata sidecars.
- Drive metadata-mirroring intent for diagnostic assets without claiming upload or label changes.
- Structured diagnostic work-window exit evidence covering triage, verified work, unverified/rushed items, deferred/blocked checks, actual errors/timeouts, planned outputs, and next safe pass.
- Five focused regression tests for complete-manifest reconciliation, stale/missing detection, duplicate stable IDs, diagnostic ZIP/sidecar metadata integrity, and structured work-window exit evidence.

### Changed
- Advanced application version to v1.12.0 and parameter baseline marker to v2.16.5; runtime/config/registry/health schemas remain `16 / 2 / 1 / 1` because no persisted-state format changed.
- Diagnostic export now reports its ZIP and SHA256 metadata sidecar to interactive and CLI users.
- Export20 operation remains report-only: the only new write is the current diagnostic checksum/metadata sidecar beside the current ZIP.
- Release ZIP metadata is embedded before hashing; release and diagnostic artifacts are never rewritten solely to add metadata after finalization.
- Documentation, known-good state, transfer brief, batch ledger, deep-check report, launcher identity, tests, and manifests were synchronized.

### Preserved
- All v1.11.1 launcher safety, identity-verified process control, report-only state protection, secret redaction, Norton boundaries, provenance-ranked health evidence, adaptive cadence, stale hysteresis, time-skew handling, and fallback diagnostics.
- No service, scheduled task, startup entry, installer, compiled binary, runtime download-and-execute, automatic restart, antivirus exclusion, execution-policy bypass, exchange/API action, or child-bot source/config edit was added.

## v1.11.1 - 2026-07-12 22:43 CDT

Timer-safe deep-alignment release against the checksum-verified ChatGPT New Thread Parameters v2.16.3 Norton Lean package. Critical safety and evidence gaps were fixed before lower-priority documentation and packaging work. v1.11.0 remains the rollback baseline.

### Critical fixes
- Disabled PowerShell execution-policy bypass as an enforceable boundary. Legacy or custom config requests for bypass are forced off, reported through config assurance, and never rendered into a launcher command.
- Strengthened diagnostic report-only behavior. Export no longer cleans interrupted temporary archives or mutates pre-existing manager evidence; collector failures are isolated and a bounded minimal diagnostic is produced if the advanced plan cannot be built.
- Added structured Norton-compatible release evidence covering source distribution, stable product/publisher identity, absent persistence/install/security-setting behavior, absent automatic exclusions, absent runtime download-and-execute, and the external/manual exact-artifact scan boundary.
- Closed a diagnostic privacy gap by adding key-context secret redaction for unknown/custom config fields such as API keys, tokens, passwords, private keys, seed phrases, access keys, credentials, and client secrets.

### Added
- Config schema v16 and parameter baseline marker v2.16.3.
- Config input-assurance reporting for recognized, preserved unknown, deprecated, forced-off, and rejected/internal keys.
- Diagnostic operation trace with run ID, wall and monotonic clocks, per-step duration, last successful step, last progress time, slowest steps, collector failures, terminal status, shutdown reason, and bounded publish retry evidence.
- Fail-isolated per-bot health/launcher audit collection and fallback diagnostic planning.
- Regression coverage for execution-policy enforcement, unknown-key preservation, context-aware redaction, report-only missing-config handling, temporary-evidence preservation, Norton/trace/config evidence, fallback export, and exported unknown-secret redaction.

### Changed
- Missing config during report-only self-test is now a warning with in-memory defaults rather than a failure or an on-disk repair.
- Stale export-temp cleanup runs only for non-export commands so diagnostics preserve interrupted-export evidence.
- Diagnostic `status.json` now carries Norton status, config assurance, data classification, operation trace, parameter baseline, and explicit collector-failure evidence within the Export20 cap.
- Documentation, known-good state, transfer brief, deep-check report, full-batch ledger, launcher identity, and manifests were synchronized to v1.11.1.

### Preserved
- v1.11.0 provenance-ranked heartbeat evidence, adaptive cadence, stale hysteresis, time-skew handling, path fingerprinting, launcher selection, and process-identity protections.
- No automatic restart, process adoption, force-stop, Norton exclusion, service, scheduled task, startup entry, installer, binary, exchange/API action, credential write, or child-bot diagnostic execution was added.
- Existing bot projects remain read-only unless the operator explicitly invokes an identity-verified control action.

### Verified
- Parameter ZIP and sidecar checksum: PASS.
- Warning-strict Python compile and compileall: PASS.
- Regression and safety tests: PASS, 99 tests.
- AST duplicate-definition, control-character, standard-library dependency, risky-pattern, literal-secret, and hard-coded-user-path checks: PASS.
- Move/rename/space-path synthetic scan, audit, status, self-test, and Export20 workflow: PASS; diagnostic ZIP valid with 19 entries.
- PC Improve packaging-log rejection, Kraken strong launcher-log selection, rolling-family continuity, config schema migration, path tokenization, minimal fallback export, and malformed-evidence preservation: PASS.

### External validation still required
- Live Windows start, stop, adopt, and force-stop operations were not executed in the Linux build environment.
- Norton-on inspection of the exact final ZIP and extracted files must be performed on the target Windows host; no detection result is claimed.
- No Drive upload or synchronization was performed.

### Rollback
- Restore v1.11.0 and its pre-v16 config backup. v1.11.0 supports config schema v15, so do not reuse a migrated v16 config without recovery. Preserve diagnostic and runtime evidence before rollback.

## v1.11.0 - 2026-07-10 10:54 CDT

Research-driven health stability release based on the real post-v1.10.1 diagnostic. The diagnostic proved that a recently modified packaging/export log could be selected as health evidence for an unrelated running utility. v1.11.0 replaces newest-file health with a bounded evidence and cadence model while preserving the no-automatic-restart boundary.

### Added
- Provenance-ranked health evidence tiers: manual, strong, standard, and none.
- Automatic exclusion of export/handoff/report/diagnostic/archive/backup/docs/test/secret/package/manifest paths from health evidence.
- Semantic runtime-directory recognition, including folders such as `launcher_logs`.
- Stable evidence-family keys across common timestamped log rotations.
- Aggregate evidence families for sibling runtime `*_latest`, `*_current`, and `*_new` logs, preserving continuity when a multi-market or multi-worker bot changes which shard is freshest.
- Bounded adaptive heartbeat cadence with robust median/MAD filtering, 32-sample cap, static-threshold floor, and configurable widening cap.
- Continuous-observation guards that reject learning across manager gaps, bot downtime, path moves, evidence-family changes, future timestamps, and mtime regressions.
- `RUNNING/SUSPECT` stale hysteresis and `RUNNING/TIME_SKEW` clock-skew classification.
- Time-gated stale confirmations so simultaneous dashboards or rapid repeated status commands cannot double-count one observation.
- Phi-like suspicion diagnostics, effective-threshold/mode/sample metrics, and bounded `state\health_state.json` schema v1.
- Bot-path fingerprinting so same-name replacement folders cannot inherit learned cadence.

### Changed
- Config schema advanced to v15 with zero-configuration health defaults.
- Strong evidence is preferred only within a bounded freshness window; old strong evidence cannot hide genuinely newer standard evidence indefinitely.
- A normal stale threshold crossing now requires confirmation; a severely overdue source can still become stale immediately.
- Dashboard, profile detail, status JSON, OpenMetrics, self-test, health audit, and diagnostic review summary expose the new evidence model.
- Diagnostic export reads health state without mutating it and embeds the snapshot inside `status.json` to preserve Export20 capacity.
- Diagnostic export now enforces byte-preserving report-only state handling: malformed config, registry, runtime, health, latest-status, metrics, and self-test files are not repaired, renamed, migrated, or rewritten.

### Preserved
- No automatic start, stop, restart, adoption, or force-stop from health evidence.
- No bot source/config changes, credentials, orders, exchange/API calls, services, scheduled tasks, startup entries, installers, binaries, or added dependencies.
- Existing identity-verified managed/adopted process control and monitor-only external-process behavior.
- v1.10.2 launcher-priority, identity-wrapper, helper-blocking, and editor false-positive fixes.

### Verified
- Python syntax compile with `SyntaxWarning` promoted to error: PASS.
- Regression and safety tests: PASS, 91 tests.
- Health provenance, sharded rolling families, adaptive cadence, time-gated hysteresis, clock skew, schema compatibility, path identity, and report-only export tests: PASS.
- Deterministic health invariant simulation: PASS, 300 scenarios x 200 observations.
- Synthetic scan/audit/status/selftest/export smoke: PASS; diagnostic integrity PASS with 19 entries.
- Final release ZIP integrity, manifest verification, release hygiene, and literal credential/private-key scan: PASS.

## v1.10.2 - 2026-07-09 06:23 CDT

Diagnostic-followup hotfix driven by the uploaded post-v1.10.1 diagnostic `botops_diagnostic_20260709_055725_134_CDT.zip`. v1.10.1 passed self-test, but the newer real diagnostic exposed three practical drift cases: an existing migrated config could still let Kalshi's raw Python engine outrank `BUYBOT.bat`; two utility tools were blocked because their project identity names contained safety-list words; and an editor/viewer process with a bot path open could look like a running bot.

### Fixed
- `BUYBOT.bat`, `SELLBOT.bat`, and `kraken.bat` now receive config-independent command-center wrapper priority, so stale existing `launcher_priority` order cannot make raw engines/helper files win again.
- Config schema v14 now promotes the current safe launcher-priority defaults before preserving user-added entries, correcting old v1.x priority order during normal migration.
- Exact root-level project identity wrappers such as `ChatGPT_Text_Chunker.bat` and `NetLossDoctor.bat` are allowed when the only blocked term is part of the project name; nested modules, report helpers, export helpers, diagnostics, tests, sidecars, and other unsafe terms remain blocked.
- Editor/viewer processes such as `notepad++.exe`, `notepad.exe`, VS Code, Office apps, Explorer, and common browsers are ignored for observed-running detection when they merely reference a bot path or launcher file. This prevents an open source/config file from appearing as `RUNNING/NO_HEARTBEAT`.

### Improved
- Added regression tests for stale launcher-priority configs, identity-name launchers, report helper blocking, and editor/viewer false-positive process detection.
- Synced Python constants, BAT launcher title/menu, README, known-good notes, transfer brief, deep-check report, full batch output, JSON manifest, and CSV manifest.

### Verified
- Python syntax compile: PASS.
- Regression tests: PASS, 71 tests.
- Synthetic scan/audit/status/selftest/export smoke: PASS.
- Smoke audit selected `BUYBOT.bat`, `ChatGPT_Text_Chunker.bat`, `NetLossDoctor.bat`, and `kraken.bat`; sidecar/report helpers stayed blocked.

### Preserved
- No trading strategy, bot config, credentials, orders, positions, services, scheduled tasks, startup entries, compiled binaries, installers, automatic restart, or exchange/API behavior changed.
- Diagnostic export remains Export20-capped, atomic, redacted, report-only, and free of child bot launcher/export execution.
- External/running bots remain monitor-only until explicitly adopted.

## v1.10.1 - 2026-07-09 04:54 CDT

Hotfix pass driven by the uploaded v1.10.0 diagnostic `botops_diagnostic_20260709_044901_550_CDT.zip`. v1.10.0 was healthy overall, but the diagnostic exposed launcher-candidate scoring risks that could make BotOps choose a raw engine/helper/test file instead of the safer command-center wrapper.

### Fixed
- Kalshi Buy now prefers `BUYBOT.bat` over raw runtime files such as `kalshi_15m_buy_bot_v67.py` when both exist.
- Explicit wrapper names `BUYBOT.bat`, `SELLBOT.bat`, and `kraken.bat` are now treated as preferred launcher names.
- Sidecar helper folders/files are blocked from automatic start selection.
- Test files are blocked from automatic stop-script selection even if their names contain stop/close terms.

### Improved
- Added config schema v13.
- Added regression tests for command-center BAT preference, sidecar launch blocking, and stop-test blocking.
- Synced BAT title/menu, Python constants, README, known-good notes, transfer brief, deep-check report, full batch output, JSON manifest, and CSV manifest.

### Preserved
- Export20 diagnostic cap, atomic export, redaction, non-mutation, and no child launcher/export execution.
- Missing-root registry preservation from v1.9.0.
- Omission-control ledger from v1.10.0.
- Monitor-only handling for external/running bots until explicit adoption.


## v1.10.0 - 2026-07-09 03:06 CDT

Timer-safe engineering pass against BotOps Manager v1.9.0 and ChatGPT New Thread Parameters v2.16.2 omission-control package. v1.9.0 remains the rollback baseline; v1.10.0 is backward-compatible and focuses on omission coverage, diagnostics/export evidence, path-targeting verification, and lean package hygiene.

### Fixed
- Updated BAT launcher title/menu version from v1.9.0 to v1.10.0.
- Removed a duplicated return statement in diagnostic archive-name deduplication.

### Improved
- Added config schema v12.
- Added diagnostic `omission_control_ledger` inside `status.json` to show checked, verified, needs-review, blocked/unknown, and omitted coverage for the effective bot root and export collectors.
- Added `diagnostic_coverage_ledger_item_limit` with bounded reporting so broad scans stay concise.
- Added omission-control checklist evidence for effective root targeting, missing-root registry protection, self-test status, final export plan, and export omissions.
- Added regression coverage for the new omission-control ledger.
- Updated README, known-good notes, deep-check report, transfer brief, full batch output, JSON manifest, and CSV manifest.

### Preserved
- No trading strategy, bot config, credentials, orders, positions, services, scheduled tasks, startup entries, installers, compiled binaries, automatic restart, or live processes were changed.
- Diagnostic export remains atomic, capped to Export20, report-only, redacted, and free of child script execution.
- External/running bots remain monitor-only until explicitly adopted.

### Verified
- Python syntax compile: PASS.
- Regression tests: PASS, 63 tests.
- Synthetic scan/audit/status/selftest/export workflow: PASS.
- Missing-root registry preservation and path-targeting evidence: PASS.
- Diagnostic omission-control ledger: PASS.
- Final package integrity and manifest verification: PASS.

### Rollback
- Restore v1.9.0 or the previous `C:\Bots\_BotOpsManager` folder. If v1.10.0 writes config schema v12 and v1.9.0 must be used, restore the pre-migration config backup from `state\` or start v1.9.0 fresh without copying v1.10.0 state.

## v1.9.0 - 2026-07-09 00:38 CDT

Timer-safe engineering pass against BotOps Manager v1.8.2 and ChatGPT New Thread Parameters v2.15.1. v1.8.2 remains the rollback baseline; v1.9.0 is backward-compatible and focuses on startup/path/config targeting, export evidence, and lean package hygiene.

### Fixed
- Missing or moved `bots_root` no longer causes a scan to rewrite the registry to an empty bot list. The prior registry is preserved and the path error is reported.
- BAT launcher display now reflects `BOTOPS_BOTS_ROOT` when set instead of always showing `C:\Bots`.
- Config output now shows effective bot root and root source, making CLI/env/config precedence visible.

### Improved
- Added config schema v11.
- Added path-targeting provenance and relocation guard evidence to self-test, environment snapshot, and diagnostic `status.json`.
- Added helper reporting for missing registry paths and registry entries outside the effective bot root.
- Updated runbook, transfer brief, known-good notes, deep-check report, full batch output, JSON manifest, and CSV manifest.

### Preserved
- No trading strategy, bot config, credentials, orders, positions, services, scheduled tasks, startup entries, installers, compiled binaries, or live processes were changed.
- Diagnostic export remains atomic, capped to Export20, report-only, redacted, and free of child script execution.
- External/running bots remain monitor-only until explicitly adopted.

### Verified
- Python syntax compile: PASS.
- Regression tests: PASS, 62 tests.
- Synthetic scan/audit/status/selftest/export workflow: PASS.
- Missing-root registry-preservation test: PASS.
- Path targeting evidence in diagnostic export: PASS.
- Final package integrity and manifest verification: PASS.

### Rollback
- Restore v1.8.2 or the previous `C:\Bots\_BotOpsManager` folder. If v1.9.0 writes config schema v11 and v1.8.2 must be used, restore the pre-migration config backup from `state\` or start v1.8.2 fresh without copying v1.9.0 state.

## v1.8.2 - 2026-07-08 04:10 CDT

Timer-safe diagnostic hotfix after `botops_diagnostic_20260708_040601_565_CDT.zip`.

- Blocked broad stop-control scripts such as `STOP_LOCAL_BOTS_AND_CLEAN_LOCKS` / `LOCAL_BOTS` from automatic stop launcher selection.
- Removed `exit` from automatic stop terms during config coercion/migration so financial scripts like `active_position_exit.py` are not treated as process-control stop handlers.
- Blocked post-stop/open-order reconciliation and active-position exit scripts from automatic stop handling.
- Classified Kalshi/prediction-market folders as `trade` instead of `unknown`, improving dashboard risk labeling and start-launcher coverage.
- Updated config schema to v10 and synced README, transfer brief, known-good notes, deep-check report, full batch output, JSON manifest, and CSV manifest.
- Preserved v1.8.1 export behavior: atomic, capped Export20, report-only, redacted, no child script execution, no live API calls.

Safety boundary: no trade logic, bot configs, credentials, orders, services, scheduled tasks, startup entries, or live processes were changed.

# Changelog

## v1.8.1 - 2026-07-08 03:35 CDT

Diagnostic-driven hotfix after reviewing `botops_diagnostic_20260708_032755_590_CDT.zip` from a live v1.8.0 run. v1.8.0 remains the rollback baseline; v1.8.1 is backward-compatible and keeps all live trading-bot controls guarded.

### Fixed
- Blocked cascade-manager start launchers such as `start_all_bots_from_manager.bat` from automatic selection. These stay monitor-only because starting them from BotOps could indirectly start many unrelated bots at once.
- Added blocked stop-control terms for scripts such as `clear_all_stop_requests.bat`, which are not true stop scripts and could manipulate another manager's control flags.
- Added config schema v9 for `blocked_stop_terms` and expanded high-risk start-term defaults. Existing config lists are merged with new safety defaults on migration.

### Improved
- Added `manager` category so folder-level bot managers/orchestrators are separated from trading/mining bots.
- Expanded utility classification for folders such as text chunkers and NetLoss/network doctor tools.
- Self-test start-launcher coverage now warns for trade/miner/likely-bot folders, while monitor-only utility/manager folders no longer create noisy coverage WARNs. Per-bot status still shows missing launchers where applicable.

### Verified
- Python syntax compile passed.
- 55 regression tests passed.
- Diagnostic review confirmed v1.8.0 export produced 19 files, stayed under the 20-file cap, and did not include bot log contents by default.
- Package ZIP integrity and manifest SHA-256 verification passed.

### Rollback
- Restore v1.8.0 or the prior `C:\Bots\_BotOpsManager` folder. If v1.8.1 writes config schema v9 and v1.8.0 must be used, restore the pre-migration config backup from `state\` or start v1.8.0 fresh without copying v1.8.1 state.

## v1.8.0 - 2026-07-08 00:06 CDT

Timer-safe engineering pass against uploaded BotOps Manager v1.7.0 and current ChatGPT New Thread Parameters v2.15.1. v1.7.0 remains the rollback baseline; v1.8.0 is backward-compatible and keeps all live trading-bot controls guarded.

### Fixed
- Export CLI now loads effective config without persisting config-schema migrations, so diagnostic export remains report-only and cannot mutate config/state just to create a handoff ZIP.
- Added version-pattern ignored-directory rules so extracted stale `BotOps_Manager_v*` release folders under `C:\Bots` are ignored rather than discovered as runnable bot projects.
- Updated BAT title/menu version from v1.7.0 to v1.8.0.

### Improved
- Added `FULL_BATCH_OUTPUT.md` to the package and diagnostic source-doc collector.
- Added config schema v8 for `ignored_dir_patterns`.
- Updated README, known-good notes, deep-check report, transfer brief, JSON manifest, and CSV manifest.

### Verified
- Python syntax compile passed.
- 53 regression tests passed.
- Synthetic scan/audit/status/selftest/export workflow passed.
- Diagnostic export ZIP integrity passed and includes final export-plan evidence.
- Final package ZIP integrity and manifest SHA-256 verification passed.

### Rollback
- Restore v1.7.0 or the prior `C:\Bots\_BotOpsManager` folder. If v1.8 writes config schema v8 and v1.7 is needed, restore the pre-migration config backup from `state\` or start v1.7 fresh without copying v1.8 state.


## v1.7.0 - 2026-07-03

Deep export-verification and lean-cleanup release for BotOps Manager. v1.6.0 remains the rollback baseline; v1.7.0 is backward-compatible and keeps all live trading-bot controls guarded.

### Fixes and hardening

- Added final Export20 plan reporting inside diagnostic `status.json`: final entry count, archive entry names, max-file cap, omission count, and omission details.
- Added a compact runtime environment snapshot to diagnostic `status.json`, including Python version/executable, platform, app root, bots root, and detected Windows/Python shell tools after path redaction.
- Added a bounded source-package inventory with per-file SHA-256 hashes so future ChatGPT reviews can verify exactly which manager files were delivered without unpacking unrelated runtime folders.
- Added config schema v7 with `diagnostic_source_inventory_file_limit` for bounded package inventory size.
- Cleaned Drive-project duplication created during prior setup by archiving the unused `SOURCE_OF_TRUTH` and `01_READY` folders under `06_ARCHIVE` instead of deleting them.
- Revalidated the launcher and diagnostic export path after the earlier cross-program export safety concern.

### Stability preserved

- Diagnostic export remains non-mutating by default and still does not execute child bot launchers, child export scripts, maintenance scripts, exchange APIs, provider probes, migrations, repairs, or installs.
- Start/stop/adopt/force-stop remain serialized by the control-action lock and limited to managed or explicitly adopted process roots.
- External running bots remain monitor-only until explicitly adopted.
- No automatic restart, service install, scheduled task, startup registration, exchange API access, credential reading, bot config edits, or trading-logic changes were added.
- No runtime Google Drive dependency was added; Drive remains only handoff/reference context.

### Validation

- Python syntax compile: PASS.
- Regression tests: PASS, 51 tests.
- Added tests for final diagnostic export-plan reporting, omitted-file reporting, runtime environment snapshot, and source-package inventory.
- Synthetic scan/audit/status/selftest/export workflow: PASS.
- Package ZIP integrity and manifest hash verification: PASS.

## v1.6.0 - 2026-06-28

Deep stability and parameter-alignment release for the uploaded ChatGPT New Thread Project Parameters v2.13.0. v1.5.0 remains the rollback baseline; v1.6.0 is backward-compatible and keeps all live trading-bot controls guarded.

### Fixes and hardening

- Updated Google Drive Project Vault references from the older flat path to `ChatGPT_Project_Vault/30_UTILITIES_AND_WINDOWS_TOOLS/BotOps_Manager`.
- Added config schema v6 Drive-vault metadata fields: `drive_vault_root`, `drive_vault_category`, `drive_vault_project`, and `drive_vault_release_subfolder`.
- Added `drive_vault_paths()` metadata serialization into diagnostic `status.json`, including project path, latest build path, ChatGPT-ready path, diagnostics path, changelog/manifest path, archive path, and expected subfolders.
- Added `MANIFEST.csv` for Drive-ready/manual upload review and included it in diagnostic exports when the Export20 cap has room.
- Sanitized Drive-vault metadata segments so malformed custom values cannot create confusing path traversal-like handoff text.
- Removed a duplicated source comment in the diagnostic export function.

### Stability preserved

- Diagnostic export remains non-mutating by default and still does not execute child bot launchers, child export scripts, maintenance scripts, exchange APIs, provider probes, migrations, repairs, or installs.
- Start/stop/adopt/force-stop remain serialized by the control-action lock and limited to managed or explicitly adopted process roots.
- External running bots remain monitor-only until explicitly adopted.
- No automatic restart, service install, scheduled task, startup registration, exchange API access, credential reading, bot config edits, or trading-logic changes were added.
- No runtime Google Drive dependency was added; Drive is only metadata/handoff/reference context.

### Validation

- Python syntax compile: PASS.
- Regression tests: PASS, 49 tests.
- Added tests for structured Drive-vault diagnostic paths, sanitized Drive-vault metadata, and CSV manifest diagnostic inclusion.
- Synthetic scan/audit/status/selftest/export workflow: PASS.
- Package ZIP integrity and manifest hash verification: PASS.

## v1.5.0 - 2026-06-28

Deep stability and parameter-alignment release for the uploaded ChatGPT New Thread Project Parameters v2.12.0. v1.4.1 remains the rollback baseline; v1.5.0 is backward-compatible and keeps all live trading-bot controls guarded.

### Fixes and hardening

- Rebuilt diagnostic export around a deterministic Export20 plan before opening the archive.
- Added same-volume temporary ZIP staging, ZIP integrity testing, entry-count enforcement, and atomic publish through `os.replace`.
- Added cleanup for abandoned `botops_diagnostic_*.zip.tmp` files with bounded retention.
- Added `diagnostic_max_files` and `diagnostic_tmp_retention_hours` config keys under config schema v5.
- Added America/Chicago diagnostic filename timestamps with the active CST/CDT label and millisecond collision protection.
- Added diagnostic evidence for Drive vault status, data classification, custom-input assurance, and resource/backpressure posture without adding extra menu clutter.
- Included `DEEP_CHECK_REPORT.md` in diagnostic exports when the Export20 cap has room.

### Stability preserved

- Diagnostic export is still non-mutating by default and still does not execute child bot launchers, child export scripts, maintenance scripts, exchange APIs, provider probes, migrations, repairs, or installs.
- Start/stop/adopt/force-stop remain serialized by the control-action lock and limited to managed or explicitly adopted process roots.
- External running bots remain monitor-only until explicitly adopted.
- No automatic restart, service install, scheduled task, startup registration, exchange API access, credential reading, bot config edits, or trading-logic changes were added.

### Validation

- Python syntax compile: PASS.
- Regression tests: PASS, 48 tests.
- Added tests for atomic diagnostic export, Export20 cap enforcement with optional logs, and stale temporary export cleanup.
- Synthetic scan/audit/status/selftest/export workflow: PASS.
- Package ZIP integrity and manifest hash verification: PASS.

## v1.4.1 - 2026-06-23

Hotfix focused on launcher/export isolation after reports that recent updates caused errors in other programs.

- Made diagnostic export non-mutating by default.
- Added `export_refresh_registry=false` config switch.
- Added explicit guarantee that diagnostic export never runs child launchers, child export BAT files, maintenance scripts, exchange APIs, or other project code.
- Added unique diagnostic ZIP naming with millisecond stamps and collision suffixes.
- Strengthened automatic launcher quarantine for handoff/support/export artifacts.
- Updated generic Python launch fallback: bot-local `.venv`, `venv`, or `env` wins; otherwise Windows uses `py -3`.
- Regression tests: PASS, 45 tests.

## v1.4.0 - 2026-06-23

- Added a project-local control-action lock for start, stop-script, adopt, and force-stop actions.
- Rechecked process inventory and root identity inside the control lock before start/adopt/force-stop proceeds.
- Added run ID traceability via `BOTOPS_RUN_ID`, manager log prefixes, diagnostic export, and child process environment variables.
- Added local integration-review evidence in diagnostics.
- Bumped config schema to v4 for control-action lock settings while preserving safe migration/backups.
- Fixed duplicate candidate printing in the log-tail helper.
- Regression coverage increased from 39 to 41 tests.

## v1.3.0 - 2026-06-20

- Added config, registry, and runtime-state schema guards so older managers refuse to overwrite or downgrade newer state.
- Added runtime and profile-time stop-scope validation so cross-child stop scripts cannot control another nested child folder.
- Added `TRANSFER_BRIEF.md` and included it in diagnostic exports.
- Regression coverage increased from 35 to 39 tests.

## v1.2.0 - 2026-06-19

- Treats nested collection folders as containers instead of one mixed runnable bot.
- Blocks shared/status/helper scripts from automatic start selection.
- Ignores report/export handoff folders during launcher discovery.
- Requires automatically selected stop scripts to share the same root/nested control scope as the selected start launcher.
- Selects `kraken.bat` for KrakenBot instead of `kraken_bot_common.py`.
- Regression coverage increased from 32 to 35 tests.

## v1.1.0 - 2026-06-19

- Replaced generic alphabetical launcher fallback with role-aware scoring.
- Blocked stop, emergency, build, deploy, export, setup, install, repair, test, demo, and similar scripts from automatic start role.
- Replaced unrestricted path-substring force-stop with managed/adopted root ownership.
- Records PID, process creation time, and launcher fingerprint to reject stale/reused process identities.
- External process matches are monitor-only until explicitly adopted.
- Fails closed when Windows process inventory is empty or cannot verify manager PID/CreationDate.
- Added safe diagnostic exports, metrics, rotating logs, atomic state writes, and 32 regression tests.

