# Changelog

## 1.13.0 — Public portfolio edition

- Preserved fail-closed launcher discovery, process-identity tracking, structured health contracts, bounded adaptive monitoring, report-only inspection, and confirmation-gated launcher control.
- Replaced environment-specific project examples with synthetic worker and service fixtures.
- Replaced private troubleshooting conventions with a generic, bounded support export.
- Removed cloud-folder routing, internal release metadata, package reconciliation, source-package inventories, and environment-specific handoff fields.
- Kept support exports integrity-tested, count- and byte-capped, redacted, non-mutating outside the managed export output, and atomically published without overwrite.
- Kept executable, setup, build, cleanup, broad-stop, and cross-project launchers blocked from automatic selection.
- Added immediate in-lock launcher revalidation, transactional incomplete-scan handling, safe-directory/reparse checks, canonical path containment, descriptor-bound bounded reads, Windows-safe archive-name enforcement, and immediate-plus-settled start-identity ownership recording.
- Added explicit successful-enumeration provenance for Windows process inventories so partial snapshots cannot authorize duplicate-sensitive control decisions.
- Deliberately disabled force termination in the public edition to eliminate PID-reuse and time-of-check/time-of-use termination risk.

This portfolio history intentionally summarizes the public engineering surface. Private build chronology, operational project names, and internal packaging records are not part of this repository.
