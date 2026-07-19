# BotOps Manager

**A safety-first local operations console for monitoring and controlling Windows automation folders.**

BotOps Manager turns a directory of independently launched tools into one observable workspace. It discovers candidate launchers, scores their safety, reads structured health contracts, tracks process identity, and produces privacy-conscious diagnostics without reading application credentials or changing business logic.

## Why it matters

Folder-based automation is convenient until an operator cannot tell which process is healthy, which launcher is safe, or whether a stop action will affect the wrong program. BotOps Manager adds an operational control plane while keeping every managed project independent.

## Engineering highlights

- **Fail-closed launcher selection:** build, deploy, export, setup, emergency-stop, and other unsafe candidates are blocked from automatic start selection.
- **Identity-bound process control:** force-stop is limited to process trees started by BotOps or explicitly adopted after review.
- **Structured health contracts:** applications can publish small JSON health/status files; log freshness remains a compatible fallback.
- **Adaptive monitoring:** repeated observations can refine stale thresholds while bounded defaults and hard limits remain in force.
- **Safe diagnostics:** exports use bounded inventories and omit operational log content by default.
- **Portable runtime:** Python 3.10+ standard library only; no service, installer, or cloud account required.

## Safety model

BotOps is monitor-only for external processes by default. It does not read exchange credentials, place orders, alter strategy files, edit source code, disable endpoint protection, or create system-wide persistence. Start and stop actions remain explicit and confirmation-gated.

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

The default root is `C:\Bots`. Use `--root` to inspect another directory without changing the saved configuration.

## Validation

```powershell
python -m unittest discover -s tests -v
python -m py_compile bot_manager.py
```

The regression suite exercises launcher classification, structured health selection, process identity, persistence boundaries, status reporting, control safeguards, metadata handling, and atomic diagnostics.

## Project status

Version 1.13.0 is a Windows-first source release. Process discovery and launcher behavior depend on Windows command and PowerShell semantics. Test fixtures isolate state and do not launch production automation.

The source retains a few legacy `project-internal` and private-vault labels because they are compatibility fields in the v1.13 diagnostic schema and regression fixtures. This public edition contains no Drive identifiers, credentials, or private operational exports.

## License

Copyright 2026 Gateway Information Group LLC. Source is shared for portfolio review under the terms in [LICENSE.md](LICENSE.md). Third-party components, if introduced by a downstream user, retain their own licenses.
