# BotOps Manager

[![Tests](https://github.com/Jnapier2/botops-manager/actions/workflows/test.yml/badge.svg)](https://github.com/Jnapier2/botops-manager/actions/workflows/test.yml)

BotOps Manager is a local Windows operations console that brings independently launched automation into one observable workspace without granting broad process authority.

It centralizes launcher-safety audits, health evidence, process ownership, and privacy-conscious support exports. Control remains limited to verified, project-scoped actions; child credentials and application logic remain untouched.

BotOps can observe every project beneath its configured root, but it controls only launchers and processes whose safety and identity it verifies again at execution time. Stale discovery data and persisted PIDs are never accepted on their own as authority to act.

## Operational safeguards

- **Fail-closed launcher selection:** setup, build, cleanup, export, test, broad-stop, and other unsafe candidates are blocked from automatic start selection; incomplete directory scans preserve prior registry and ownership state.
- **Re-audited process control:** start and project-scoped stop scripts are rechecked for containment, file type, role, and score immediately before launch.
- **Structured health contracts:** child applications can publish small JSON health files; provenance-ranked log freshness remains a fallback.
- **Adaptive monitoring:** repeated observations can refine stale thresholds while bounded defaults, hysteresis, and hard limits remain active.
- **Report-only support:** exports are atomic, capped, redacted, integrity-tested, and non-mutating by default.
- **Portable runtime:** Python 3.10+ standard library only; no service, installer, cloud account, or compiled binary is required.

## Safety boundary

BotOps is monitor-only for externally started processes by default. It does not read child-project credentials, call external services on their behalf, edit their source or configuration, install persistence, weaken endpoint protection, or restart a project automatically.

Start and stop-script actions are explicit and confirmation-gated. Duplicate checks require an explicitly complete Windows process inventory.

BotOps records start ownership only when the launched process remains live and the same PID and creation identity are verified both immediately and after the settle window. Force termination remains disabled because a persisted PID alone cannot eliminate Windows process-reuse and time-of-check/time-of-use risk.

## Quick start

On Windows with Python 3.10 or newer:

```powershell
python bot_manager.py --root "C:\path\to\automation" audit
python bot_manager.py --root "C:\path\to\automation" status
```

For the interactive dashboard, run `BotOps_Manager.bat` or:

```powershell
python bot_manager.py --root "C:\path\to\automation" menu
```

The default root is `C:\Bots`. Use `--root` to inspect another directory without persisting that override.

That root is the primary operating boundary: discovery, registry checks, and control decisions remain scoped beneath it.

## Support export

```powershell
python bot_manager.py --root "C:\path\to\automation" export
```

Each export contains bounded status, launcher-audit, health-audit, self-test, and redacted state summaries. Child-project log bodies remain excluded; a byte-bounded, redacted manager-log tail is included only when one already exists.

The exporter enforces per-entry and total byte limits, Windows-safe archive names, descriptor-bound staging, no-overwrite publication, and link/reparse checks. It never uploads a support bundle; review each ZIP before sharing it.

## Validation

```powershell
python -m compileall -q bot_manager.py tests
python -m unittest discover -s tests -v
```

The deterministic suite uses synthetic folders and mocked process inventories. It does not start child automation, contact network services, or modify system security settings.

Copyright © 2026 Gateway Information Group LLC. All rights reserved. See [LICENSE.md](LICENSE.md).
