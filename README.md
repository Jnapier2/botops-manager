# BotOps Manager

A safety-first local operations console for monitoring and controlling independent Windows automation folders.

BotOps Manager turns a directory of separately launched tools into one observable workspace. It discovers candidate launchers, scores their safety, reads structured health contracts, tracks process identity, and creates privacy-conscious support exports without reading application credentials or changing child-project logic.

## Engineering highlights

- **Fail-closed launcher selection:** setup, build, cleanup, export, test, broad-stop, and other unsafe candidates are blocked from automatic start selection; incomplete directory scans preserve prior registry and ownership state.
- **Re-audited process control:** start and project-scoped stop scripts are rechecked for containment, file type, role, and score immediately before launch.
- **Structured health contracts:** child applications can publish small JSON health files; provenance-ranked log freshness remains a fallback.
- **Adaptive monitoring:** repeated observations can refine stale thresholds while bounded defaults, hysteresis, and hard limits remain active.
- **Report-only support:** exports are atomic, capped, redacted, integrity-tested, and non-mutating by default.
- **Portable runtime:** Python 3.10+ standard library only; no service, installer, cloud account, or compiled binary is required.

## Safety boundary

BotOps is monitor-only for externally started processes by default. It does not read child-project credentials, call external services on their behalf, edit their source or configuration, install persistence, weaken endpoint protection, or restart a project automatically.

Start and stop-script actions are explicit and confirmation-gated. Duplicate checks require an explicitly complete Windows process inventory. BotOps records start ownership only when the launched process remains live and the same PID and creation identity are verified both immediately and after the settle window. Force termination is deliberately disabled in this public edition because a persisted PID alone cannot eliminate Windows process-reuse and time-of-check/time-of-use risk.

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

## Support export

```powershell
python bot_manager.py --root "C:\path\to\automation" export
```

The export contains bounded status, launcher-audit, health-audit, self-test, and redacted state summaries. Child-project log bodies are excluded; a byte-bounded, redacted manager-log tail is included only when one already exists. Per-entry and total byte limits, Windows-safe archive names, descriptor-bound staging, no-overwrite publication, and link/reparse checks are enforced. Review every ZIP before sharing it; no support bundle is uploaded automatically.

## Validation

```powershell
python -m compileall -q bot_manager.py tests
python -m unittest discover -s tests -v
```

The deterministic suite uses synthetic folders and mocked process inventories. It does not start child automation, contact network services, or modify system security settings.

## Portfolio context

This public edition excludes private builds, cloud-folder mappings, real operational project names, binaries, runtime state, logs, and generated support bundles. The repository demonstrates defensive local orchestration, evidence-ranked health monitoring, redaction, bounded recovery, and fail-closed control boundaries.

Copyright © 2026 Gateway Information Group LLC. All rights reserved. See [LICENSE.md](LICENSE.md).
