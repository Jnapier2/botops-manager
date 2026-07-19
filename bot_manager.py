#!/usr/bin/env python3
"""
BotOps Manager v1.13.0
Asset metadata: ID BOTOPS-CORE; class source; role manager-core; status current; sensitivity project-internal; tags botops-manager,windows,supervision,asset-metadata.
Local Windows-first monitor/controller for bot folders under C:\\Bots.

Safety boundary:
- The manager does not change trading strategy/configuration files, read exchange
  credentials, place orders, or edit bot source code.
- Automatic launcher detection blocks stop/emergency/build/deploy/export/setup
  scripts from being used as start commands.
- Force-stop is limited to process roots that BotOps started or that the user
  explicitly adopted after review.
- External processes remain monitor-only by default.

Dependencies: Python 3.10+ standard library only.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import datetime as dt
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import math
import ntpath
import os
import re
import shutil
import statistics
import subprocess
import sys
import textwrap
import time
import zipfile
try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - Python builds without zoneinfo are rare.
    ZoneInfo = None  # type: ignore[assignment]
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

APP_NAME = "BotOps Manager"
APP_VERSION = "1.13.0"
CONFIG_VERSION = 17
REGISTRY_VERSION = 2
RUNTIME_VERSION = 1
HEALTH_STATE_VERSION = 1
PARAMETER_BASELINE = "v2.16.5"
NORTON_STATUS_SCHEMA = "norton_status_v1"
ASSET_MANIFEST_SCHEMA = "botops_asset_manifest_v1"
ASSET_METADATA_SCHEMA = "botops_asset_metadata_v1"
HEALTH_CONTRACT_SCHEMA = "botops_health_v1"
HEALTH_CONTRACT_RELATIVE_PATHS = (
    ".botops/health.json",
    ".botops/status.json",
    "runtime/botops_health.json",
    "runtime/botops_status.json",
    "botops_health.json",
    "botops_status.json",
)
HEALTH_CONTRACT_STATES = {"starting", "ready", "degraded", "stopping", "stopped", "failed"}
PROJECT_SLUG = "botops-manager"
RELEASE_ASSET_ID = "BOTOPS-RELEASE"
DIAGNOSTIC_ASSET_FAMILY_ID = "BOTOPS-DIAGNOSTIC"
ASSET_MANIFEST_REQUIRED_FIELDS = {
    "asset_id", "path", "title", "purpose", "asset_class", "role", "format",
    "project_slug", "version", "status", "sensitivity", "source_of_truth",
    "tags", "aliases", "lineage", "created_cdt", "modified_cdt", "size_bytes", "sha256",
}
ASSET_MANIFEST_HASH_SENTINELS = {
    "SELF_REFERENTIAL_SEE_RELEASE_SHA256_SIDECAR",
    "self-referential-generated-after-write",
}
PRODUCT_PUBLISHER = "Unsigned local source package"
DEFAULT_BOTS_ROOT = r"C:\Bots"
DRIVE_VAULT_ROOT = "ChatGPT_Project_Vault"
DRIVE_VAULT_CATEGORY = "30_UTILITIES_AND_WINDOWS_TOOLS"
DRIVE_VAULT_PROJECT = "BotOps_Manager"
DRIVE_VAULT_LAYOUT_FOLDERS = [
    "00_SOURCE_OF_TRUTH",
    "01_CHATGPT_READY",
    "02_LATEST_BUILD",
    "03_DIAGNOSTICS",
    "04_DOCS_RUNBOOK",
    "05_CHANGELOG_MANIFEST",
    "06_ARCHIVE",
]
DRIVE_VAULT_RELEASE_SUBFOLDER = "02_LATEST_BUILD"
RUN_ID = os.environ.get("BOTOPS_RUN_ID") or f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{os.getpid():x}"

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": CONFIG_VERSION,
    "bots_root": DEFAULT_BOTS_ROOT,
    "drive_vault_root": DRIVE_VAULT_ROOT,
    "drive_vault_category": DRIVE_VAULT_CATEGORY,
    "drive_vault_project": DRIVE_VAULT_PROJECT,
    "drive_vault_release_subfolder": DRIVE_VAULT_RELEASE_SUBFOLDER,
    "stale_minutes": 10,
    "startup_grace_minutes": 3,
    "scan_immediate_child_folders_only": True,
    "scan_nested_collections": True,
    "nested_collection_depth": 3,
    "launcher_search_depth": 2,
    "max_launcher_candidates_per_bot": 300,
    "max_log_search_files_per_bot": 350,
    "log_search_depth": 4,
    "log_min_score": 35,
    "min_start_score": 60,
    "min_stop_score": 50,
    "confirm_start_stop": True,
    "control_managed_processes_only": True,
    "max_adopt_roots": 16,
    "max_force_stop_roots": 16,
    "start_settle_seconds": 1.5,
    "stop_wait_seconds": 8,
    "watch_interval_seconds": 10,
    "watch_rescan_seconds": 120,
    "process_cache_seconds": 2,
    "log_cache_seconds": 5,
    "adaptive_health_enabled": True,
    "adaptive_health_min_samples": 5,
    "adaptive_health_max_threshold_factor": 6.0,
    "health_stale_confirmations": 2,
    "health_hard_stale_factor": 2.0,
    "health_future_skew_seconds": 120,
    "health_contract_max_bytes": 65536,
    "control_action_lock_timeout_seconds": 20,
    "control_action_lock_stale_seconds": 300,
    "powershell_execution_policy_bypass": False,
    "diagnostics_include_log_content": False,
    "diagnostic_log_file_limit": 3,
    "export_refresh_registry": False,
    "diagnostic_max_files": 20,
    "diagnostic_tmp_retention_hours": 24,
    "diagnostic_source_inventory_file_limit": 40,
    "diagnostic_coverage_ledger_item_limit": 200,
    "ignored_dirs": [
        ".git",
        ".idea",
        ".vscode",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "node_modules",
        "venv",
        ".venv",
        "env",
        ".env",
        "dist",
        "build",
        "logs_old",
        "archive",
        "archives",
        "backup",
        "backups",
        "tmp",
        "temp",
        "state",
        "exports",
        "diagnostics",
        "reports",
        "report",
        "chatgpt_export",
        "chatgpt_export_20",
        "chatgpt_handoff",
        "security_false_positive_kit",
        "_BotOpsManager",
        "BotOps_Manager",
        "BotOps_Manager_v1.0.0",
        "BotOps_Manager_v1.1.0",
        "BotOps_Manager_v1.2.0",
        "BotOps_Manager_v1.3.0",
        "BotOps_Manager_v1.4.0",
        "BotOps_Manager_v1.4.1",
        "BotOps_Manager_v1.5.0",
        "BotOps_Manager_v1.6.0",
        "BotOps_Manager_v1.7.0",
        "BotOps_Manager_v1.8.0",
        "BotOps_Manager_v1.8.1",
        "BotOps_Manager_v1.8.2",
        "BotOps_Manager_v1.9.0",
        "BotOps_Manager_v1.10.0",
        "BotOps_Manager_v1.10.1",
        "BotOps_Manager_v1.10.2",
        "BotOps_Manager_v1.11.0",
        "BotOps_Manager_v1.11.1",
        "BotOps_Manager_v1.12.0",
    ],
    "ignored_dir_patterns": [
        r"BotOps_Manager_v\d+\.\d+\.\d+",
        r"BotOps_Manager_v\d+\.\d+\.\d+_.+",
    ],
    "launcher_priority": [
        "start.bat",
        "run.bat",
        "launch.bat",
        "buybot.bat",
        "sellbot.bat",
        "kraken.bat",
        "bot.bat",
        "start.cmd",
        "run.cmd",
        "launch.cmd",
        "start.ps1",
        "run.ps1",
        "main.py",
        "bot.py",
        "trade_bot.py",
        "trader.py",
        "app.py",
        "__main__.py",
        "index.js",
        "server.js",
        "package.json",
    ],
    "blocked_start_terms": [
        "stop",
        "emergency",
        "kill",
        "shutdown",
        "close",
        "terminate",
        "uninstall",
        "delete",
        "remove",
        "reset",
        "cleanup",
        "clean_up",
        "export",
        "chatgpt",
        "diagnostic",
        "diagnostics",
        "report",
        "smoke",
        "backtest",
        "test",
        "tests",
        "pytest",
        "unittest",
        "benchmark",
        "bench",
        "demo",
        "example",
        "sample",
        "development",
        "dev",
        "setup",
        "status",
        "health",
        "probe",
        "doctor",
        "validate",
        "validator",
        "common",
        "audit",
        "retry",
        "helper",
        "optimizer",
        "preflight",
        "selftest",
        "self_test",
        "install",
        "update",
        "upgrade",
        "deploy",
        "build",
        "compile",
        "compiler",
        "package",
        "backup",
        "restore",
        "migrate",
        "inspect",
        "repair",
        "unblock",
        "start_all",
        "run_all",
        "launch_all",
        "all_bots",
        "allbots",
        "from_manager",
        "first_run",
        "help",
        "readme",
        "prompt",
        "starter",
        "instructions",
        "upload",
        "handoff",
        "transfer",
        "support",
        "bundle",
        "collect",
        "collector",
        "snapshot",
        "dump",
        "integrity",
        "checksum",
        "sha256",
        "patch",
        "launcher_check",
        "sidecar",
        "sidecars",
    ],
    "positive_start_terms": [
        "start",
        "run",
        "launch",
        "main",
        "trade",
        "trader",
        "bot",
        "daemon",
        "live",
        "production",
        "prod",
        "worker",
        "server",
        "miner",
    ],
    "stop_terms": ["stop", "shutdown", "close", "terminate", "emergency", "kill"],
    "blocked_stop_terms": [
        "clear_all",
        "all_stop_requests",
        "all_bots",
        "local_bots",
        "stop_all_bots",
        "stop_local_bots",
        "kill_all_bots",
        "shutdown_all_bots",
        "from_manager",
        "manager",
        "reconciliation",
        "reconcile",
        "open_order",
        "active_position",
        "position_exit",
        "test",
        "tests",
        "pytest",
        "unittest",
        "sidecar",
        "sidecars",
    ],
    "log_extensions": [".log", ".txt", ".jsonl", ".csv"],
    "log_dir_names": ["logs", "log", "output", "outputs", "runtime"],
    "log_positive_terms": [
        "log",
        "event",
        "events",
        "heartbeat",
        "health",
        "activity",
        "trade",
        "trades",
        "order",
        "orders",
        "fill",
        "fills",
        "balance",
        "position",
        "positions",
        "status",
        "runtime",
        "websocket",
        "ws",
        "error",
        "stdout",
        "stderr",
        "miner",
    ],
    "log_negative_terms": [
        "readme",
        "changelog",
        "manifest",
        "version",
        "license",
        "requirements",
        "export",
        "chatgpt",
        "paste",
        "diagnostic",
        "diagnostics",
        "package",
        "compiler",
        "install",
        "setup",
        "known_good",
        "rollback",
        "template",
        "example",
        "full_batch",
        "zip_creation",
        "transfer",
        "secret",
        "credential",
    ],
    "health_excluded_path_terms": [
        "export",
        "chatgpt",
        "diagnostic",
        "report",
        "archive",
        "backup",
        "documentation",
        "docs",
        "example",
        "test",
        "secret",
        "credential",
        "handoff",
        "transfer",
        "package",
        "manifest",
    ],
}

HEALTH_SAMPLE_WINDOW = 32
HEALTH_INTERVAL_MULTIPLIER = 3.0
HEALTH_MIN_STDDEV_SECONDS = 5.0
HEALTH_ACCEPTABLE_PAUSE_SECONDS = 30.0

SUPPORTED_LAUNCH_SUFFIXES = {".bat", ".cmd", ".py", ".ps1", ".js", ".exe"}
GENERIC_LAUNCHER_NAMES = {
    "start.bat",
    "run.bat",
    "launch.bat",
    "bot.bat",
    "start.cmd",
    "run.cmd",
    "launch.cmd",
    "start.ps1",
    "run.ps1",
    "main.py",
    "bot.py",
    "app.py",
    "index.js",
    "server.js",
    "package.json",
}
COMMAND_CENTER_LAUNCHER_NAMES = {"buybot.bat", "sellbot.bat", "kraken.bat"}
PROJECT_IDENTITY_START_TERMS = {"chatgpt", "doctor"}
NON_RUNTIME_PATH_PROCESS_NAMES = {
    "notepad.exe",
    "notepad++.exe",
    "wordpad.exe",
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "code.exe",
    "code - insiders.exe",
    "devenv.exe",
    "sublime_text.exe",
    "atom.exe",
    "explorer.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
}
WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    "com1",
    "com2",
    "com3",
    "com4",
    "lpt1",
    "lpt2",
    "lpt3",
}

SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?(?:key|secret)|secret|access[_-]?token|refresh[_-]?token|token|password|passwd|passphrase|private[_-]?key|wallet[_-]?key|seed(?:[_-]?phrase)?)\b"
    r"\s*[:=]\s*(?:['\"][^'\"\r\n]*['\"]|[^\s,;\r\n]+)"
)
BEARER_RE = re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{8,}")
KNOWN_TOKEN_RE = re.compile(
    r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[opusr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{16,}|AIza[A-Za-z0-9_-]{20,})\b"
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
URL_CREDENTIAL_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)([^/@:\s]+):([^/@\s]+)@")
SENSITIVE_DIAGNOSTIC_KEYS = {
    "api_key",
    "apikey",
    "api_secret",
    "client_secret",
    "secret",
    "access_key",
    "access_token",
    "refresh_token",
    "auth_token",
    "session_token",
    "token",
    "tokens",
    "password",
    "passwd",
    "pwd",
    "passphrase",
    "private_key",
    "secret_key",
    "wallet_key",
    "seed",
    "seed_phrase",
    "cookie",
    "cookies",
    "credential",
    "credentials",
}

_LOGGER: Optional[logging.Logger] = None
_PROCESS_CACHE: Tuple[float, List["ProcessInfo"]] = (0.0, [])
_LOG_CANDIDATE_CACHE: Dict[str, Tuple[float, List["LogCandidate"]]] = {}
_STATE_READ_ONLY_DEPTH = 0


@dataclass
class ProcessInfo:
    pid: int
    name: str
    executable_path: str = ""
    command_line: str = ""
    parent_pid: Optional[int] = None
    creation_time: Optional[float] = None
    working_set_bytes: int = 0

    @property
    def searchable_text(self) -> str:
        return normalize_text_path(f"{self.name} {self.executable_path} {self.command_line}")


@dataclass
class LauncherCandidate:
    path: str
    kind: str
    role: str
    score: int
    blocked: bool
    reasons: List[str]


@dataclass
class LogCandidate:
    path: str
    score: int
    reliable: bool
    mtime: Optional[float]
    reasons: List[str]
    tier: str = "none"
    family: str = ""
    evidence_kind: str = "file"
    contract_schema: str = ""
    contract_state: str = ""
    contract_live: Optional[bool] = None
    contract_ready: Optional[bool] = None
    contract_pid: Optional[int] = None
    contract_process_started_at_epoch: Optional[float] = None
    contract_heartbeat_sequence: Optional[int] = None
    contract_progress_sequence: Optional[int] = None
    contract_updated_at: str = ""
    contract_updated_at_epoch: Optional[float] = None
    contract_timestamp_skew: bool = False
    contract_message: str = ""
    contract_version: str = ""
    contract_errors: List[str] = field(default_factory=list)


@dataclass
class BotRecord:
    name: str
    path: str
    launcher: str = ""
    launcher_kind: str = "none"
    launcher_manual: bool = False
    launcher_approved: bool = False
    launcher_safe: bool = False
    launcher_score: int = 0
    launcher_reason: str = ""
    stop_launcher: str = ""
    stop_launcher_kind: str = "none"
    stop_launcher_manual: bool = False
    heartbeat_file: str = ""
    heartbeat_manual: bool = False
    stale_minutes: Optional[float] = None
    enabled: bool = True
    category: str = "unknown"
    category_manual: bool = False
    notes: str = ""
    detected_at: str = ""
    last_seen_at: str = ""


@dataclass
class TrackingResult:
    managed_processes: List[ProcessInfo]
    managed_roots: List[ProcessInfo]
    observed_processes: List[ProcessInfo]
    observed_roots: List[ProcessInfo]
    observed_confidence: str
    observed_reasons: List[str]


@dataclass
class BotStatus:
    bot: BotRecord
    status: str
    control_state: str
    root_pids: List[int]
    process_count: int
    process_names: List[str]
    last_log: str = ""
    last_log_mtime: Optional[float] = None
    last_log_age_minutes: Optional[float] = None
    health_reliable: bool = False
    health_score: int = 0
    health_tier: str = "none"
    health_mode: str = "none"
    health_effective_threshold_minutes: Optional[float] = None
    health_suspicion: Optional[float] = None
    health_sample_count: int = 0
    health_evidence_count: int = 0
    health_advanced: bool = False
    health_clock_skew: bool = False
    health_evidence_kind: str = "none"
    health_contract_state: str = ""
    health_contract_live: Optional[bool] = None
    health_contract_ready: Optional[bool] = None
    health_contract_pid: Optional[int] = None
    health_contract_pid_match: Optional[bool] = None
    health_contract_heartbeat_sequence: Optional[int] = None
    health_contract_progress_sequence: Optional[int] = None
    health_contract_message: str = ""
    health_contract_errors: List[str] = field(default_factory=list)
    launcher_exists: bool = False
    stop_launcher_exists: bool = False
    warnings: List[str] = field(default_factory=list)


@dataclass
class HealthAssessment:
    age_minutes: Optional[float]
    static_threshold_minutes: float
    effective_threshold_minutes: float
    mode: str
    suspicion: Optional[float]
    sample_count: int
    advanced: bool
    clock_skew: bool
    suspect: bool
    stale_confirmed: bool
    consecutive_suspect: int
    learned_interval_seconds: Optional[float]
    state_changed: bool
    notes: List[str] = field(default_factory=list)


def app_root() -> Path:
    return Path(__file__).resolve().parent


def is_windows_host() -> bool:
    return os.name == "nt"


def state_dir() -> Path:
    path = app_root() / "state"
    path.mkdir(parents=True, exist_ok=True)
    return path


def logs_dir() -> Path:
    path = app_root() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def exports_dir() -> Path:
    path = app_root() / "exports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_path() -> Path:
    return state_dir() / "bot_manager_config.json"


def registry_path() -> Path:
    return state_dir() / "bot_registry.json"


def runtime_state_path() -> Path:
    return state_dir() / "runtime_state.json"


def health_state_path() -> Path:
    return state_dir() / "health_state.json"


def latest_status_path() -> Path:
    return state_dir() / "latest_status.json"


def metrics_path() -> Path:
    return state_dir() / "botops_metrics.prom"


def last_selftest_path() -> Path:
    return state_dir() / "last_selftest.json"


def manager_log_path() -> Path:
    return logs_dir() / "bot_manager.log"


def utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def chicago_now() -> dt.datetime:
    if ZoneInfo is not None:
        try:
            return dt.datetime.now(ZoneInfo("America/Chicago"))
        except Exception:
            pass
    return dt.datetime.now().astimezone()


def local_stamp_for_filename() -> str:
    # Include milliseconds and the actual local CST/CDT abbreviation so quick
    # diagnostic exports do not collide and filenames remain Windows-safe.
    now = chicago_now()
    zone = re.sub(r"[^A-Za-z0-9]+", "", now.tzname() or "LOCAL") or "LOCAL"
    return now.strftime("%Y%m%d_%H%M%S_") + f"{now.microsecond // 1000:03d}_{zone}"


def clean_drive_vault_segment(value: Any, default: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    # Drive path segments are metadata only. Keep them predictable, readable,
    # and safe for manual upload/merge instructions.
    text = text.strip("/.")
    text = re.sub(r"[^A-Za-z0-9._ -]+", "_", text)
    text = re.sub(r"\s+", "_", text).strip("_.-")
    if not text or text in {".", ".."}:
        return default
    return text[:80]


def drive_vault_paths(cfg: Dict[str, Any]) -> Dict[str, Any]:
    root = clean_drive_vault_segment(cfg.get("drive_vault_root"), DRIVE_VAULT_ROOT)
    category = clean_drive_vault_segment(cfg.get("drive_vault_category"), DRIVE_VAULT_CATEGORY)
    project = clean_drive_vault_segment(cfg.get("drive_vault_project"), DRIVE_VAULT_PROJECT)
    release_subfolder = clean_drive_vault_segment(cfg.get("drive_vault_release_subfolder"), DRIVE_VAULT_RELEASE_SUBFOLDER)
    project_path = "/".join([root, category, project])
    return {
        "root": root,
        "category": category,
        "project": project,
        "project_path": project_path,
        "source_of_truth_path": f"{project_path}/00_SOURCE_OF_TRUTH",
        "chatgpt_ready_path": f"{project_path}/01_CHATGPT_READY",
        "latest_build_path": f"{project_path}/{release_subfolder}",
        "diagnostics_path": f"{project_path}/03_DIAGNOSTICS",
        "docs_runbook_path": f"{project_path}/04_DOCS_RUNBOOK",
        "changelog_manifest_path": f"{project_path}/05_CHANGELOG_MANIFEST",
        "archive_path": f"{project_path}/06_ARCHIVE",
        "expected_subfolders": list(DRIVE_VAULT_LAYOUT_FOLDERS),
    }


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    for index in range(2, 1000):
        candidate = path.with_name(f"{stem}_{index}{suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not create a unique output path for {path}")


def _get_logger() -> logging.Logger:
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER
    logger = logging.getLogger("botops")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = RotatingFileHandler(
            manager_log_path(),
            maxBytes=2_000_000,
            backupCount=3,
            encoding="utf-8",
            delay=True,
        )
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%S"))
        logger.addHandler(handler)
    _LOGGER = logger
    return logger


def redact(value: str) -> str:
    """Redact contextual secrets without redacting long, harmless bot names."""
    out = str(value)
    out = PRIVATE_KEY_RE.sub("***REDACTED_PRIVATE_KEY***", out)
    out = SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=***REDACTED***", out)
    out = BEARER_RE.sub(lambda m: f"{m.group(1)}***REDACTED***", out)
    out = KNOWN_TOKEN_RE.sub("***REDACTED_TOKEN***", out)
    out = URL_CREDENTIAL_RE.sub(lambda m: f"{m.group(1)}***REDACTED***:***REDACTED***@", out)
    return out


def log_event(message: str, level: str = "INFO") -> None:
    try:
        logger = _get_logger()
        method = getattr(logger, level.lower(), logger.info)
        method(redact(f"run_id={RUN_ID} {message}"))
    except Exception:
        pass


def normalize_text_path(value: str) -> str:
    return str(value).strip().strip('"').lower().replace("/", "\\")


def safe_stat(path: Path) -> Optional[os.stat_result]:
    try:
        return path.stat()
    except Exception:
        return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def chicago_metadata_stamp(value: Optional[dt.datetime] = None) -> str:
    now = value or chicago_now()
    return now.strftime("%Y-%m-%d %I:%M:%S %p %Z") + " / America/Chicago"


def retained_source_files(root: Optional[Path] = None) -> List[Path]:
    """Return packaged source assets while excluding runtime/transient folders."""
    base = (root or app_root()).resolve()
    ignored_top = {"state", "logs", "exports", "__pycache__", ".pytest_cache", ".git", ".venv", "venv"}
    retained: List[Path] = []
    try:
        candidates = sorted((path for path in base.rglob("*") if path.is_file()), key=lambda item: item.as_posix().lower())
    except Exception:
        return retained
    for path in candidates:
        try:
            rel = path.resolve().relative_to(base)
        except Exception:
            continue
        if rel.parts and rel.parts[0] in ignored_top:
            continue
        if rel.name.lower().endswith((".pyc", ".pyo", ".tmp")):
            continue
        retained.append(path)
    return retained


def read_asset_manifest(root: Optional[Path] = None) -> Tuple[Optional[Dict[str, Any]], str]:
    manifest_path = (root or app_root()) / "MANIFEST.json"
    if not manifest_path.exists():
        return None, "manifest_missing"
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"manifest_unreadable: {redact(str(exc))}"
    if not isinstance(payload, dict):
        return None, "manifest_root_not_object"
    return payload, "ok"


def manifest_asset_index(root: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    payload, status = read_asset_manifest(root)
    if payload is None or status != "ok":
        return {}
    assets = payload.get("assets")
    if not isinstance(assets, list):
        assets = payload.get("files")
    if not isinstance(assets, list):
        return {}
    index: Dict[str, Dict[str, Any]] = {}
    for item in assets:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").replace("\\", "/")
        while path.startswith("./"):
            path = path[2:]
        path = path.lstrip("/")
        if path and path not in index:
            index[path] = item
    return index


def build_asset_metadata_reconciliation(root: Optional[Path] = None) -> Dict[str, Any]:
    """Validate canonical source asset records without mutating the package."""
    base = (root or app_root()).resolve()
    generated = chicago_metadata_stamp()
    payload, read_status = read_asset_manifest(base)
    result: Dict[str, Any] = {
        "schema": ASSET_METADATA_SCHEMA,
        "parameter_baseline": PARAMETER_BASELINE,
        "generated_cdt": generated,
        "manifest_path": "MANIFEST.json",
        "manifest_read_status": read_status,
        "status": "WARN",
        "summary": {},
        "missing_records": [],
        "stale_records": [],
        "conflicts": [],
        "unsupported": [],
        "header_gaps": [],
    }
    if payload is None:
        result["summary"] = {"retained_files": len(retained_source_files(base)), "manifest_records": 0}
        result["unsupported"].append("canonical MANIFEST.json unavailable; filename/path remains the only local identity")
        return result

    schema = str(payload.get("schema") or "")
    if schema != ASSET_MANIFEST_SCHEMA:
        result["conflicts"].append(f"manifest schema={schema or 'missing'} expected={ASSET_MANIFEST_SCHEMA}")
    assets = payload.get("assets")
    if not isinstance(assets, list):
        result["conflicts"].append("manifest assets must be a list")
        assets = []

    actual_files = retained_source_files(base)
    actual_by_path = {path.relative_to(base).as_posix(): path for path in actual_files}
    records_by_path: Dict[str, Dict[str, Any]] = {}
    seen_ids: Set[str] = set()
    duplicate_ids: Set[str] = set()
    duplicate_paths: Set[str] = set()

    for raw in assets:
        if not isinstance(raw, dict):
            result["conflicts"].append("manifest contains a non-object asset record")
            continue
        missing_fields = sorted(ASSET_MANIFEST_REQUIRED_FIELDS - set(raw))
        path_text = str(raw.get("path") or "").replace("\\", "/")
        while path_text.startswith("./"):
            path_text = path_text[2:]
        path_text = path_text.lstrip("/")
        asset_id = str(raw.get("asset_id") or "").strip()
        if missing_fields:
            result["conflicts"].append(f"{path_text or '<missing path>'}: missing fields {missing_fields}")
        if not path_text or path_text.startswith("/") or ".." in Path(path_text).parts:
            result["conflicts"].append(f"unsafe or missing manifest path: {path_text or '<missing>'}")
            continue
        if path_text in records_by_path:
            duplicate_paths.add(path_text)
        else:
            records_by_path[path_text] = raw
        if asset_id:
            if asset_id in seen_ids:
                duplicate_ids.add(asset_id)
            seen_ids.add(asset_id)
        else:
            result["conflicts"].append(f"{path_text}: missing stable asset_id")
        if raw.get("project_slug") != PROJECT_SLUG:
            result["conflicts"].append(f"{path_text}: project_slug mismatch")
        if not isinstance(raw.get("tags"), list) or not raw.get("tags"):
            result["conflicts"].append(f"{path_text}: controlled tags must be a non-empty list")
        if not isinstance(raw.get("aliases"), list):
            result["conflicts"].append(f"{path_text}: aliases must be a list")

    if duplicate_paths:
        result["conflicts"].append("duplicate paths: " + ", ".join(sorted(duplicate_paths)))
    if duplicate_ids:
        result["conflicts"].append("duplicate asset IDs: " + ", ".join(sorted(duplicate_ids)))

    for rel, path in actual_by_path.items():
        record = records_by_path.get(rel)
        if record is None:
            result["missing_records"].append(rel)
            continue
        try:
            stat = path.stat()
            expected_size = record.get("size_bytes")
            if isinstance(expected_size, int) and expected_size != stat.st_size:
                result["stale_records"].append(f"{rel}: size {stat.st_size} != manifest {expected_size}")
            elif not isinstance(expected_size, int):
                result["conflicts"].append(f"{rel}: size_bytes must be an integer")
            expected_hash = str(record.get("sha256") or "")
            if expected_hash in ASSET_MANIFEST_HASH_SENTINELS:
                result["unsupported"].append(f"{rel}: self-referential hash recorded through release SHA256 sidecar")
            elif re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                actual_hash = sha256_file(path)
                if actual_hash != expected_hash:
                    result["stale_records"].append(f"{rel}: SHA256 mismatch")
            else:
                result["conflicts"].append(f"{rel}: invalid or missing SHA256")
        except Exception as exc:
            result["unsupported"].append(f"{rel}: verification unavailable: {redact(str(exc))}")

        role = str(record.get("role") or "")
        if role not in {"asset-registry", "asset-registry-mirror"}:
            try:
                header = path.read_text(encoding="utf-8", errors="replace")[:4096]
                asset_id = str(record.get("asset_id") or "")
                if asset_id and asset_id not in header:
                    result["header_gaps"].append(f"{rel}: key header does not expose asset ID {asset_id}")
            except Exception:
                result["unsupported"].append(f"{rel}: embedded/header metadata unsupported")

    for rel in sorted(set(records_by_path) - set(actual_by_path)):
        result["conflicts"].append(f"manifest record has no packaged file: {rel}")

    release_asset = payload.get("release_asset")
    if not isinstance(release_asset, dict):
        result["conflicts"].append("release_asset metadata is missing")
    else:
        for field_name in ("asset_id", "path", "version", "status", "sensitivity", "tags", "lineage"):
            if field_name not in release_asset:
                result["conflicts"].append(f"release_asset missing field: {field_name}")
        if release_asset.get("asset_id") != RELEASE_ASSET_ID:
            result["conflicts"].append("release_asset stable ID mismatch")

    result["summary"] = {
        "retained_files": len(actual_by_path),
        "manifest_records": len(records_by_path),
        "source_of_truth_records": sum(1 for item in records_by_path.values() if item.get("source_of_truth") is True),
        "missing_count": len(result["missing_records"]),
        "stale_count": len(result["stale_records"]),
        "conflict_count": len(result["conflicts"]),
        "header_gap_count": len(result["header_gaps"]),
        "unsupported_count": len(result["unsupported"]),
    }
    unexpected_unsupported = [item for item in result["unsupported"] if "self-referential hash" not in item]
    result["summary"]["unexpected_unsupported_count"] = len(unexpected_unsupported)
    if result["missing_records"] or result["stale_records"] or result["conflicts"] or result["header_gaps"]:
        result["status"] = "FAIL"
    elif unexpected_unsupported:
        result["status"] = "WARN"
    else:
        result["status"] = "PASS"
    return result


def diagnostic_asset_metadata(export_path: Path, *, created: Optional[dt.datetime] = None) -> Dict[str, Any]:
    now = created or chicago_now()
    run_token = re.sub(r"[^A-Za-z0-9]+", "-", RUN_ID).strip("-")[:80] or "RUN"
    asset_id = f"{DIAGNOSTIC_ASSET_FAMILY_ID}-{run_token}"
    sidecar_name = f"{export_path.name}.sha256.txt"
    return {
        "schema": ASSET_METADATA_SCHEMA,
        "asset_id": asset_id,
        "asset_family_id": DIAGNOSTIC_ASSET_FAMILY_ID,
        "path": export_path.name,
        "title": f"{APP_NAME} Export20 diagnostic",
        "purpose": "Read-only redacted operational handoff and recovery evidence",
        "asset_class": "diagnostic",
        "role": "export20",
        "format": "zip",
        "project_slug": PROJECT_SLUG,
        "project_run_id": RUN_ID,
        "version": APP_VERSION,
        "status": "current",
        "sensitivity": "project-internal",
        "source_of_truth": False,
        "tags": ["botops-manager", "diagnostic", "export20", "windows", "asset-metadata"],
        "aliases": ["BotOps diagnostic", "BotOps handoff export"],
        "lineage": f"derived from {RELEASE_ASSET_ID}@v{APP_VERSION}",
        "created_cdt": chicago_metadata_stamp(now),
        "modified_cdt": chicago_metadata_stamp(now),
        "size_bytes": "finalized in adjacent SHA256 sidecar",
        "sha256": "finalized in adjacent SHA256 sidecar",
        "hash_delivery": sidecar_name,
        "companion_assets": [
            {
                "asset_id": f"{asset_id}-SHA256",
                "path": sidecar_name,
                "title": f"{APP_NAME} diagnostic SHA256 and metadata sidecar",
                "purpose": "Final archive identity, checksum, size, and metadata delivery",
                "asset_class": "checksum",
                "role": "checksum-sidecar",
                "format": "txt",
                "project_slug": PROJECT_SLUG,
                "version": APP_VERSION,
                "status": "current",
                "sensitivity": "project-internal",
                "source_of_truth": False,
                "tags": ["botops-manager", "diagnostic", "sha256", "asset-metadata"],
                "aliases": ["BotOps diagnostic checksum"],
                "lineage": f"validates {asset_id}",
                "created_cdt": chicago_metadata_stamp(now),
                "modified_cdt": chicago_metadata_stamp(now),
                "size_bytes": "self-referential sidecar content",
                "sha256": "SELF_REFERENTIAL_SIDECAR",
            }
        ],
    }


def diagnostic_zip_comment(metadata: Dict[str, Any]) -> bytes:
    compact = {
        "schema": metadata.get("schema"),
        "asset_id": metadata.get("asset_id"),
        "asset_family_id": metadata.get("asset_family_id"),
        "project_slug": metadata.get("project_slug"),
        "project_run_id": metadata.get("project_run_id"),
        "version": metadata.get("version"),
        "status": metadata.get("status"),
        "sensitivity": metadata.get("sensitivity"),
        "tags": metadata.get("tags"),
        "lineage": metadata.get("lineage"),
    }
    payload = json.dumps(compact, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > 65535:
        raise ValueError("Diagnostic ZIP metadata comment exceeds ZIP format limit")
    return payload


def write_diagnostic_sha256_sidecar(export_path: Path, metadata: Dict[str, Any]) -> Path:
    digest = sha256_file(export_path)
    size = export_path.stat().st_size
    sidecar = export_path.with_name(export_path.name + ".sha256.txt")
    lines = [
        f"{digest}  {export_path.name}",
        f"# asset_id={metadata.get('asset_id', '')}",
        f"# asset_family_id={metadata.get('asset_family_id', '')}",
        f"# sidecar_asset_id={metadata.get('companion_assets', [{}])[0].get('asset_id', '')}",
        f"# project_slug={PROJECT_SLUG}",
        f"# project_run_id={RUN_ID}",
        f"# version={APP_VERSION}",
        "# status=current",
        "# sensitivity=project-internal",
        f"# size_bytes={size}",
        f"# lineage={metadata.get('lineage', '')}",
        f"# tags={','.join(str(item) for item in metadata.get('tags', []))}",
        f"# generated_cdt={chicago_metadata_stamp()}",
    ]
    atomic_write_text(sidecar, "\n".join(lines) + "\n", lock=False)
    return sidecar


def safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value).strip())
    cleaned = cleaned.strip("._ ") or "item"
    if cleaned.lower() in WINDOWS_RESERVED_NAMES:
        cleaned += "_file"
    return cleaned[:120]


def sanitize_title(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9 ._\-]+", "_", value)[:80] or "Bot"


def deep_merge(default: Dict[str, Any], existing: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(default)
    for key, value in existing.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(merged[key], value)  # type: ignore[arg-type]
        else:
            merged[key] = value
    return merged


def config_input_assurance(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Summarize effective config handling without exposing secret values."""
    unknown = sorted({str(item) for item in cfg.get("_config_unknown_keys", []) if str(item).strip()})
    deprecated = sorted({str(item) for item in cfg.get("_config_deprecated_keys", []) if str(item).strip()})
    findings = [str(item) for item in cfg.get("_config_findings", []) if str(item).strip()]
    return {
        "schema": "config_input_assurance_v1",
        "parameter_baseline": PARAMETER_BASELINE,
        "unknown_keys": unknown,
        "deprecated_or_forced_off_keys": deprecated,
        "findings": findings,
        "unknown_key_behavior": "preserved_in_config_and_reported_not_silently_ignored",
        "critical_input_behavior": "safety-critical controls are normalized and fail closed",
        "powershell_execution_policy_bypass_effective": False,
    }


def path_is_manager_state(path: Path) -> bool:
    try:
        path.resolve().relative_to((app_root() / "state").resolve())
        return True
    except Exception:
        return False


@contextlib.contextmanager
def report_only_state_mode() -> Iterator[None]:
    """Prevent diagnostic/report paths from repairing or writing manager state."""
    global _STATE_READ_ONLY_DEPTH
    _STATE_READ_ONLY_DEPTH += 1
    try:
        yield
    finally:
        _STATE_READ_ONLY_DEPTH = max(0, _STATE_READ_ONLY_DEPTH - 1)


def manager_state_is_read_only() -> bool:
    return _STATE_READ_ONLY_DEPTH > 0


@contextlib.contextmanager
def state_write_lock(timeout_seconds: float = 3.0) -> Iterator[None]:
    """Small cross-process lock for state writes; stale locks self-heal."""
    lock_path = state_dir() / ".write.lock"
    deadline = time.monotonic() + max(0.1, timeout_seconds)
    acquired = False
    while time.monotonic() < deadline:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            payload = json.dumps({"pid": os.getpid(), "created_at": time.time()})
            os.write(fd, payload.encode("utf-8"))
            os.close(fd)
            acquired = True
            break
        except FileExistsError:
            try:
                raw = json.loads(lock_path.read_text(encoding="utf-8"))
                if time.time() - float(raw.get("created_at", 0)) > 30:
                    lock_path.unlink(missing_ok=True)
                    continue
            except Exception:
                try:
                    if time.time() - lock_path.stat().st_mtime > 30:
                        lock_path.unlink(missing_ok=True)
                        continue
                except Exception:
                    pass
            time.sleep(0.05)
    if not acquired:
        raise TimeoutError(f"Timed out waiting for state lock: {lock_path}")
    try:
        yield
    finally:
        try:
            lock_path.unlink(missing_ok=True)
        except Exception:
            pass


def control_action_lock_path() -> Path:
    return state_dir() / ".control_action.lock"


def read_control_action_lock() -> Dict[str, Any]:
    path = control_action_lock_path()
    if not path.exists():
        return {"active": False}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raw = {}
    except Exception:
        raw = {}
    created_epoch = 0.0
    try:
        created_epoch = float(raw.get("created_at_epoch", 0) or 0)
    except Exception:
        created_epoch = 0.0
    age_seconds = max(0.0, time.time() - created_epoch) if created_epoch else None
    raw.update({"active": True, "path": str(path), "age_seconds": age_seconds})
    return raw


@contextlib.contextmanager
def control_action_lock(bot_name: str, action: str, cfg: Dict[str, Any]) -> Iterator[None]:
    """Serialize risky start/stop/adopt/force-stop control actions.

    Multiple BotOps windows may safely monitor at the same time, but mutable
    control actions must not race. The lock is deliberately file-local and
    transparent so it works without elevation and shows up in diagnostics.
    """
    lock_path = control_action_lock_path()
    timeout_seconds = max(1.0, float(cfg.get("control_action_lock_timeout_seconds", 20)))
    stale_seconds = max(60.0, float(cfg.get("control_action_lock_stale_seconds", 300)))
    deadline = time.monotonic() + timeout_seconds
    payload = {
        "pid": os.getpid(),
        "run_id": RUN_ID,
        "action": str(action),
        "bot_name": str(bot_name),
        "created_at": utc_stamp(),
        "created_at_epoch": time.time(),
    }
    acquired = False
    last_owner: Dict[str, Any] = {}
    while time.monotonic() <= deadline:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, (json.dumps(payload, indent=2) + "\n").encode("utf-8"))
            finally:
                os.close(fd)
            acquired = True
            break
        except FileExistsError:
            owner = read_control_action_lock()
            last_owner = owner
            age = owner.get("age_seconds")
            if isinstance(age, (int, float)) and age > stale_seconds:
                try:
                    lock_path.unlink(missing_ok=True)
                    log_event(
                        f"Recovered stale control-action lock for action={owner.get('action', '?')} bot={owner.get('bot_name', '?')} age_seconds={age:.1f}",
                        "WARNING",
                    )
                    continue
                except Exception:
                    pass
            time.sleep(0.1)
    if not acquired:
        owner_desc = f"action={last_owner.get('action', '?')} bot={last_owner.get('bot_name', '?')} pid={last_owner.get('pid', '?')}"
        raise TimeoutError(f"Another BotOps control action is active ({owner_desc}). Try again after it completes.")
    try:
        yield
    finally:
        try:
            lock_path.unlink(missing_ok=True)
        except Exception:
            pass


def atomic_write_text(path: Path, text: str, *, backup: bool = False, lock: bool = True) -> None:
    if manager_state_is_read_only() and path_is_manager_state(path):
        raise RuntimeError(f"Report-only mode blocked manager state mutation: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)

    def perform() -> None:
        temp = path.with_name(f".{path.name}.{os.getpid()}.{int(time.time() * 1000)}.tmp")
        try:
            with temp.open("w", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
                stream.flush()
                try:
                    os.fsync(stream.fileno())
                except OSError:
                    pass
            if backup and path.exists():
                try:
                    shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
                except Exception:
                    pass
            last_exc: Optional[Exception] = None
            for attempt in range(4):
                try:
                    os.replace(temp, path)
                    return
                except Exception as exc:  # antivirus/indexer can briefly hold files on Windows
                    last_exc = exc
                    time.sleep(0.08 * (attempt + 1))
            if last_exc:
                raise last_exc
        finally:
            try:
                temp.unlink(missing_ok=True)
            except Exception:
                pass

    if lock:
        with state_write_lock():
            perform()
    else:
        perform()


def write_json(path: Path, data: Any, *, backup: bool = False, lock: bool = True) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, sort_keys=False) + "\n", backup=backup, lock=lock)


def load_json(path: Path, default: Any, label: str, *, recover: bool = True) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        if not recover or manager_state_is_read_only():
            log_event(
                f"{label} could not be read; report-only/read-only mode left it unchanged: {exc}",
                "WARNING",
            )
            return default
        broken = path.with_suffix(path.suffix + f".broken_{local_stamp_for_filename()}")
        try:
            path.replace(broken)
        except Exception:
            pass
        log_event(f"{label} could not be read and was moved aside: {exc}", "WARNING")
        return default




def schema_version_value(data: Any, default: int = 0) -> int:
    if not isinstance(data, dict):
        return default
    raw = data.get("version", default)
    try:
        return int(raw)
    except Exception:
        try:
            return int(float(str(raw)))
        except Exception:
            return default


def raw_json_no_recovery(path: Path) -> Optional[Any]:
    """Read JSON for schema checks without moving or rewriting the file."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def file_schema_version(path: Path) -> Optional[int]:
    raw = raw_json_no_recovery(path)
    if not isinstance(raw, dict) or "version" not in raw:
        return None
    return schema_version_value(raw, default=0)


def schema_newer_than(path: Path, supported_version: int) -> Optional[int]:
    version = file_schema_version(path)
    if version is not None and version > supported_version:
        return version
    return None


def control_state_schema_warnings() -> List[str]:
    checks = [
        ("config", config_path(), CONFIG_VERSION),
        ("registry", registry_path(), REGISTRY_VERSION),
        ("runtime_state", runtime_state_path(), RUNTIME_VERSION),
    ]
    warnings: List[str] = []
    for label, path, supported in checks:
        newer = schema_newer_than(path, supported)
        if newer is not None:
            warnings.append(
                f"{label} schema version {newer} is newer than supported version {supported}; this manager will not overwrite or downgrade it."
            )
    return warnings


def state_schema_warnings() -> List[str]:
    warnings = control_state_schema_warnings()
    newer = schema_newer_than(health_state_path(), HEALTH_STATE_VERSION)
    if newer is not None:
        warnings.append(
            f"health_state schema version {newer} is newer than supported version {HEALTH_STATE_VERSION}; adaptive health learning is disabled for this run and the file will not be changed."
        )
    return warnings


def control_schema_block_reason() -> str:
    warnings = control_state_schema_warnings()
    if not warnings:
        return ""
    return "Control action blocked by schema guard: " + " ".join(warnings)


def assert_not_newer_schema(path: Path, supported_version: int, label: str) -> None:
    newer = schema_newer_than(path, supported_version)
    if newer is not None:
        raise RuntimeError(
            f"Refused to overwrite {label}: schema version {newer} is newer than this manager supports ({supported_version})."
        )


def _coerce_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    unknown_keys = sorted(
        str(key)
        for key in cfg
        if not str(key).startswith("_") and key not in DEFAULT_CONFIG
    )
    findings: List[str] = []
    deprecated_keys: List[str] = []
    raw_bypass_request = cfg.get("powershell_execution_policy_bypass", False)

    numeric_nonnegative = [
        "stale_minutes",
        "startup_grace_minutes",
        "launcher_search_depth",
        "nested_collection_depth",
        "max_launcher_candidates_per_bot",
        "max_log_search_files_per_bot",
        "log_search_depth",
        "log_min_score",
        "min_start_score",
        "min_stop_score",
        "max_adopt_roots",
        "max_force_stop_roots",
        "start_settle_seconds",
        "stop_wait_seconds",
        "control_action_lock_timeout_seconds",
        "control_action_lock_stale_seconds",
        "watch_interval_seconds",
        "watch_rescan_seconds",
        "process_cache_seconds",
        "log_cache_seconds",
        "adaptive_health_min_samples",
        "adaptive_health_max_threshold_factor",
        "health_stale_confirmations",
        "health_hard_stale_factor",
        "health_future_skew_seconds",
        "health_contract_max_bytes",
        "diagnostic_log_file_limit",
        "diagnostic_max_files",
        "diagnostic_tmp_retention_hours",
        "diagnostic_source_inventory_file_limit",
        "diagnostic_coverage_ledger_item_limit",
    ]
    for key in numeric_nonnegative:
        try:
            value = float(cfg[key])
            if value < 0:
                raise ValueError
            if key in {
                "launcher_search_depth",
                "nested_collection_depth",
                "max_launcher_candidates_per_bot",
                "max_log_search_files_per_bot",
                "log_search_depth",
                "log_min_score",
                "min_start_score",
                "min_stop_score",
                "max_adopt_roots",
                "max_force_stop_roots",
                "watch_interval_seconds",
                "watch_rescan_seconds",
                "adaptive_health_min_samples",
                "health_stale_confirmations",
                "health_future_skew_seconds",
                "health_contract_max_bytes",
                "diagnostic_log_file_limit",
                "diagnostic_max_files",
                "diagnostic_tmp_retention_hours",
                "diagnostic_source_inventory_file_limit",
                "diagnostic_coverage_ledger_item_limit",
            }:
                cfg[key] = int(value)
            else:
                cfg[key] = value
        except Exception:
            cfg[key] = DEFAULT_CONFIG[key]

    # Keep safety-critical defaults during upgrades from v1 configs, while
    # preserving any user-added entries and their ordering.
    list_keys = [
        "ignored_dirs",
        "ignored_dir_patterns",
        "launcher_priority",
        "blocked_start_terms",
        "positive_start_terms",
        "stop_terms",
        "blocked_stop_terms",
        "log_extensions",
        "log_dir_names",
        "log_positive_terms",
        "log_negative_terms",
        "health_excluded_path_terms",
    ]
    for key in list_keys:
        raw_values = cfg.get(key, [])
        values = raw_values if isinstance(raw_values, list) else []
        combined: List[str] = []
        seen: Set[str] = set()
        # Launcher priority is operationally important: existing configs should
        # inherit the current safe wrapper order instead of preserving stale
        # v1.x order that can let raw engines outrank command-center BATs.
        source_values = [*DEFAULT_CONFIG.get(key, []), *values] if key == "launcher_priority" else [*values, *DEFAULT_CONFIG.get(key, [])]
        for item in source_values:
            text = str(item).strip()
            marker = text.lower()
            if text and marker not in seen:
                seen.add(marker)
                combined.append(text)
        cfg[key] = combined

    # Stop launchers are control operations, not trading/position-exit actions.
    # Older configs included "exit" as a stop term; remove it so scripts like
    # active_position_exit.py cannot become automatic stop handlers.
    cfg["stop_terms"] = [term for term in cfg.get("stop_terms", []) if str(term).strip().lower() != "exit"]

    bool_keys = [
        "scan_immediate_child_folders_only",
        "scan_nested_collections",
        "confirm_start_stop",
        "control_managed_processes_only",
        "powershell_execution_policy_bypass",
        "diagnostics_include_log_content",
        "export_refresh_registry",
        "adaptive_health_enabled",
    ]
    for key in bool_keys:
        value = cfg.get(key, DEFAULT_CONFIG[key])
        if isinstance(value, bool):
            cfg[key] = value
        elif isinstance(value, (int, float)):
            cfg[key] = bool(value)
        elif isinstance(value, str) and value.strip().lower() in {"1", "true", "yes", "on"}:
            cfg[key] = True
        elif isinstance(value, str) and value.strip().lower() in {"0", "false", "no", "off"}:
            cfg[key] = False
        else:
            cfg[key] = DEFAULT_CONFIG[key]

    if bool(cfg.get("powershell_execution_policy_bypass", False)):
        deprecated_keys.append("powershell_execution_policy_bypass")
        findings.append(
            "powershell_execution_policy_bypass was requested but is forced off; BotOps never launches PowerShell with -ExecutionPolicy Bypass"
        )
    elif isinstance(raw_bypass_request, str) and raw_bypass_request.strip():
        # Preserve a truthful note when a malformed non-empty value was supplied.
        normalized = raw_bypass_request.strip().lower()
        if normalized not in {"0", "false", "no", "off"}:
            deprecated_keys.append("powershell_execution_policy_bypass")
            findings.append("invalid powershell_execution_policy_bypass input was ignored and forced off")
    cfg["powershell_execution_policy_bypass"] = False

    # This is a non-negotiable safety invariant, not an opt-out switch.
    cfg["control_managed_processes_only"] = True
    # Lower automatic thresholds would revive the v1 "pick any helper script"
    # failure mode. Low-score candidates can still be chosen explicitly in a
    # per-bot profile after review.
    cfg["nested_collection_depth"] = max(1, min(5, int(cfg.get("nested_collection_depth", 3))))
    cfg["min_start_score"] = max(60, int(cfg.get("min_start_score", 60)))
    cfg["min_stop_score"] = max(50, int(cfg.get("min_stop_score", 50)))
    cfg["max_adopt_roots"] = max(1, min(32, int(cfg.get("max_adopt_roots", 16))))
    cfg["max_force_stop_roots"] = max(1, min(32, int(cfg.get("max_force_stop_roots", 16))))
    cfg["control_action_lock_timeout_seconds"] = max(1, min(120, int(cfg.get("control_action_lock_timeout_seconds", 20))))
    cfg["control_action_lock_stale_seconds"] = max(60, min(1800, int(cfg.get("control_action_lock_stale_seconds", 300))))
    cfg["adaptive_health_min_samples"] = max(3, min(20, int(cfg.get("adaptive_health_min_samples", 5))))
    cfg["adaptive_health_max_threshold_factor"] = max(
        1.0, min(24.0, float(cfg.get("adaptive_health_max_threshold_factor", 6.0)))
    )
    cfg["health_stale_confirmations"] = max(1, min(5, int(cfg.get("health_stale_confirmations", 2))))
    cfg["health_hard_stale_factor"] = max(1.0, min(10.0, float(cfg.get("health_hard_stale_factor", 2.0))))
    cfg["health_future_skew_seconds"] = max(0, min(3600, int(cfg.get("health_future_skew_seconds", 120))))
    cfg["health_contract_max_bytes"] = max(1024, min(1024 * 1024, int(cfg.get("health_contract_max_bytes", 65536))))
    cfg["diagnostic_max_files"] = max(12, min(20, int(cfg.get("diagnostic_max_files", 20))))
    cfg["diagnostic_tmp_retention_hours"] = max(1, min(168, int(cfg.get("diagnostic_tmp_retention_hours", 24))))
    cfg["diagnostic_source_inventory_file_limit"] = max(10, min(250, int(cfg.get("diagnostic_source_inventory_file_limit", 40))))
    cfg["diagnostic_coverage_ledger_item_limit"] = max(20, min(500, int(cfg.get("diagnostic_coverage_ledger_item_limit", 200))))

    root = cfg.get("bots_root", DEFAULT_BOTS_ROOT)
    cfg["bots_root"] = str(root).strip() or DEFAULT_BOTS_ROOT
    cfg["drive_vault_root"] = clean_drive_vault_segment(cfg.get("drive_vault_root"), DRIVE_VAULT_ROOT)
    cfg["drive_vault_category"] = clean_drive_vault_segment(cfg.get("drive_vault_category"), DRIVE_VAULT_CATEGORY)
    cfg["drive_vault_project"] = clean_drive_vault_segment(cfg.get("drive_vault_project"), DRIVE_VAULT_PROJECT)
    cfg["drive_vault_release_subfolder"] = clean_drive_vault_segment(cfg.get("drive_vault_release_subfolder"), DRIVE_VAULT_RELEASE_SUBFOLDER)
    cfg["_config_unknown_keys"] = unknown_keys
    cfg["_config_deprecated_keys"] = deprecated_keys
    cfg["_config_findings"] = findings
    cfg["version"] = CONFIG_VERSION
    return cfg


def load_config(
    root_override: Optional[str] = None,
    persist_migrations: bool = True,
    recover_corrupt: bool = True,
) -> Dict[str, Any]:
    path = config_path()
    raw = load_json(path, {}, "Config", recover=recover_corrupt) if path.exists() else {}
    if not isinstance(raw, dict):
        raw = {}
    if schema_version_value(raw, default=0) > CONFIG_VERSION:
        cfg = _coerce_config(copy.deepcopy(DEFAULT_CONFIG))
        cfg["_schema_guard_warnings"] = state_schema_warnings()
        log_event("Config schema is newer than this manager supports; using safe defaults for this run and leaving the config file untouched.", "WARNING")
    else:
        cfg = _coerce_config(deep_merge(copy.deepcopy(DEFAULT_CONFIG), raw))
        persisted = {key: value for key, value in cfg.items() if not str(key).startswith("_")}
        if raw != persisted and persist_migrations:
            try:
                assert_not_newer_schema(path, CONFIG_VERSION, "config")
                write_json(path, persisted, backup=path.exists())
            except Exception as exc:
                log_event(f"Could not persist migrated config: {exc}", "WARNING")
    env_root = os.environ.get("BOTOPS_BOTS_ROOT")
    root_source = "config" if "bots_root" in raw else "default"
    if root_override:
        cfg["bots_root"] = root_override
        root_source = "cli --root"
    elif env_root:
        cfg["bots_root"] = env_root
        root_source = "BOTOPS_BOTS_ROOT"
    cfg["_bots_root_source"] = root_source
    return cfg


def read_registry() -> Dict[str, Any]:
    default = {"version": REGISTRY_VERSION, "updated_at": "", "bots": {}}
    raw = load_json(registry_path(), default, "Registry")
    if not isinstance(raw, dict):
        return default
    raw.setdefault("updated_at", "")
    raw.setdefault("bots", {})
    if not isinstance(raw["bots"], dict):
        raw["bots"] = {}
    if schema_version_value(raw, default=0) > REGISTRY_VERSION:
        raw["__newer_schema_blocked"] = True
        return raw
    raw.setdefault("version", REGISTRY_VERSION)
    raw["version"] = REGISTRY_VERSION
    return raw


def write_registry(registry: Dict[str, Any]) -> None:
    assert_not_newer_schema(registry_path(), REGISTRY_VERSION, "registry")
    registry["version"] = REGISTRY_VERSION
    registry["updated_at"] = utc_stamp()
    registry.pop("__newer_schema_blocked", None)
    write_json(registry_path(), registry, backup=True)


def read_runtime_state() -> Dict[str, Any]:
    default = {"version": RUNTIME_VERSION, "updated_at": "", "bots": {}}
    raw = load_json(runtime_state_path(), default, "Runtime state")
    if not isinstance(raw, dict):
        return default
    raw.setdefault("updated_at", "")
    raw.setdefault("bots", {})
    if not isinstance(raw["bots"], dict):
        raw["bots"] = {}
    if schema_version_value(raw, default=0) > RUNTIME_VERSION:
        raw["__newer_schema_blocked"] = True
        return raw
    raw.setdefault("version", RUNTIME_VERSION)
    return raw


def write_runtime_state(state: Dict[str, Any]) -> None:
    assert_not_newer_schema(runtime_state_path(), RUNTIME_VERSION, "runtime state")
    state["version"] = RUNTIME_VERSION
    state["updated_at"] = utc_stamp()
    state.pop("__newer_schema_blocked", None)
    write_json(runtime_state_path(), state, backup=True)


def read_health_state() -> Dict[str, Any]:
    default = {"version": HEALTH_STATE_VERSION, "updated_at": "", "bots": {}}
    raw = load_json(health_state_path(), default, "Health state")
    if not isinstance(raw, dict):
        return default
    raw.setdefault("updated_at", "")
    raw.setdefault("bots", {})
    if not isinstance(raw["bots"], dict):
        raw["bots"] = {}
    if schema_version_value(raw, default=0) > HEALTH_STATE_VERSION:
        raw["__newer_schema_blocked"] = True
        return raw
    raw.setdefault("version", HEALTH_STATE_VERSION)
    return raw


def write_health_state(state: Dict[str, Any]) -> None:
    assert_not_newer_schema(health_state_path(), HEALTH_STATE_VERSION, "health state")
    state["version"] = HEALTH_STATE_VERSION
    state["updated_at"] = utc_stamp()
    state.pop("__newer_schema_blocked", None)
    # This is bounded, reconstructable observation history rather than control
    # ownership. Atomic replacement is retained, but backup churn is avoided.
    write_json(health_state_path(), state, backup=False)


def prune_runtime_state(valid_bot_names: Set[str]) -> None:
    state = read_runtime_state()
    bots = state.get("bots", {}) if isinstance(state.get("bots"), dict) else {}
    removed = [name for name in list(bots) if name not in valid_bot_names]
    if not removed:
        return
    for name in removed:
        bots.pop(name, None)
    state["bots"] = bots
    write_runtime_state(state)
    log_event("Removed orphan runtime ownership for: " + ", ".join(sorted(removed)))


def prune_health_state(valid_bot_names: Set[str]) -> None:
    state = read_health_state()
    if state.get("__newer_schema_blocked"):
        return
    bots = state.get("bots", {}) if isinstance(state.get("bots"), dict) else {}
    removed = [name for name in list(bots) if name not in valid_bot_names]
    if not removed:
        return
    for name in removed:
        bots.pop(name, None)
    state["bots"] = bots
    write_health_state(state)
    log_event("Removed orphan adaptive health history for: " + ", ".join(sorted(removed)))


def bot_record_from_dict(name: str, data: Dict[str, Any]) -> BotRecord:
    allowed = {field.name for field in fields(BotRecord)}
    merged: Dict[str, Any] = {"name": name, "path": str(data.get("path", ""))}
    for key, value in data.items():
        if key in allowed:
            merged[key] = value
    try:
        stale = merged.get("stale_minutes")
        merged["stale_minutes"] = float(stale) if stale not in (None, "") else None
    except Exception:
        merged["stale_minutes"] = None
    return BotRecord(**merged)


def path_depth_relative(base: Path, child: Path) -> int:
    try:
        return len(child.relative_to(base).parts)
    except Exception:
        return 9999


def is_ignored_dir(path: Path, cfg: Dict[str, Any], manager_root: Optional[Path] = None) -> bool:
    name = path.name.lower()
    ignored = {str(item).lower() for item in cfg.get("ignored_dirs", [])}
    if name in ignored:
        return True
    for pattern in cfg.get("ignored_dir_patterns", []):
        try:
            if re.fullmatch(str(pattern), path.name, flags=re.IGNORECASE):
                return True
        except re.error:
            log_event(f"Ignoring invalid ignored_dir_patterns entry: {pattern!r}", "WARNING")
    if manager_root is not None:
        try:
            if path.resolve() == manager_root.resolve():
                return True
        except Exception:
            pass
    return False


def launcher_kind(path: Path) -> str:
    if path.name.lower() == "package.json":
        return "npm"
    return {
        ".bat": "batch",
        ".cmd": "batch",
        ".py": "python",
        ".ps1": "powershell",
        ".js": "node",
        ".exe": "executable",
    }.get(path.suffix.lower(), "file")


def tokenize_name(value: str) -> Set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", value.lower()) if token}


def compact_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def term_matches_name(term: str, stem: str, tokens: Set[str]) -> bool:
    """Match filename terms conservatively; avoid short substring accidents."""
    term = str(term).lower().strip()
    if not term:
        return False
    if term in tokens:
        return True
    normalized_stem = re.sub(r"[-.]+", "_", stem.lower())
    normalized_term = re.sub(r"[-.]+", "_", term)
    if "_" in normalized_term:
        return normalized_term in normalized_stem
    if len(normalized_term) >= 5:
        return normalized_term in normalized_stem
    return normalized_stem == normalized_term or normalized_stem.startswith(normalized_term + "_") or normalized_stem.endswith("_" + normalized_term)


def candidate_launcher_files(folder: Path, cfg: Dict[str, Any]) -> List[Path]:
    max_depth = int(cfg.get("launcher_search_depth", 2))
    max_candidates = int(cfg.get("max_launcher_candidates_per_bot", 300))
    manager_root = app_root()
    found: Dict[str, Path] = {}
    try:
        for current, dirs, files in os.walk(folder):
            current_path = Path(current)
            dirs[:] = [name for name in dirs if not is_ignored_dir(current_path / name, cfg, manager_root)]
            depth = path_depth_relative(folder, current_path)
            if depth > max_depth:
                dirs[:] = []
                continue
            for filename in files:
                path = current_path / filename
                if (path.suffix.lower() in SUPPORTED_LAUNCH_SUFFIXES or filename.lower() == "package.json") and is_path_within(path, folder):
                    found[str(path).lower()] = path
                    if len(found) >= max_candidates:
                        return list(found.values())
    except Exception:
        pass
    return list(found.values())


def package_has_start_script(path: Path) -> bool:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        scripts = raw.get("scripts", {}) if isinstance(raw, dict) else {}
        return isinstance(scripts, dict) and bool(scripts.get("start"))
    except Exception:
        return False


def score_start_candidate(path: Path, folder: Path, cfg: Dict[str, Any]) -> LauncherCandidate:
    kind = launcher_kind(path)
    reasons: List[str] = []
    blocked = False
    score = {"batch": 30, "executable": 27, "python": 24, "powershell": 20, "node": 18, "npm": 15}.get(kind, 5)
    reasons.append(f"{kind} launcher")
    depth = path_depth_relative(folder, path.parent)
    if depth == 0:
        score += 20
        reasons.append("bot root")
    else:
        score -= min(20, depth * 4)

    support_parent_terms: Set[str] = {"sidecar", "sidecars"}
    try:
        parent_parts = [part.lower() for part in path.relative_to(folder).parts[:-1]]
    except Exception:
        parent_parts = []
    if any(any(term in part for term in support_parent_terms) for part in parent_parts):
        blocked = True
        score -= 220
        reasons.append("blocked support folder: sidecar")

    name_lower = path.name.lower()
    stem_lower = path.stem.lower()
    tokens = tokenize_name(stem_lower)
    compact_stem = compact_name(stem_lower)
    compact_folder = compact_name(folder.name)
    folder_tokens = tokenize_name(folder.name)

    priority = [str(item).lower() for item in cfg.get("launcher_priority", [])]
    priority_bonus = max(45, 110 - priority.index(name_lower) * 3) if name_lower in priority else 0
    command_center_bonus = 115 if name_lower in COMMAND_CENTER_LAUNCHER_NAMES else 0
    bonus = max(priority_bonus, command_center_bonus)
    if bonus:
        score += bonus
        if command_center_bonus:
            reasons.append("command-center wrapper")
        else:
            reasons.append("preferred launcher name")

    positive_terms = [str(item).lower() for item in cfg.get("positive_start_terms", [])]
    positive_hits = [term for term in positive_terms if term in tokens or stem_lower.startswith(term + "_") or stem_lower == term]
    if positive_hits:
        score += min(70, 30 + 12 * (len(positive_hits) - 1))
        reasons.append("start terms: " + ", ".join(sorted(set(positive_hits))))

    if kind in {"batch", "powershell"} and stem_lower.startswith("start"):
        score += 35
        reasons.append("explicit start prefix")
    elif kind in {"batch", "powershell"} and stem_lower.startswith("run"):
        score += 12
        reasons.append("explicit run prefix")

    if compact_stem and compact_folder:
        common_tokens = {token for token in tokens & folder_tokens if len(token) >= 4 and token not in {"start", "main", "run", "bot"}}
        if compact_stem == compact_folder or compact_folder.startswith(compact_stem) or compact_stem.startswith(compact_folder):
            score += 35
            reasons.append("matches bot folder name")
        elif common_tokens:
            score += 28
            reasons.append("shares bot-name token")

    blocked_terms = [str(item).lower() for item in cfg.get("blocked_start_terms", [])]
    # package.json is a legitimate npm entry point when scripts.start exists.
    # Do not let the generic "package" safety term block that exact file.
    blocked_hits = [
        term
        for term in blocked_terms
        if term_matches_name(term, stem_lower, tokens) and not (kind == "npm" and term == "package")
    ]
    root_identity_wrapper = bool(
        depth == 0
        and kind in {"batch", "powershell", "executable"}
        and compact_stem
        and compact_folder
        and compact_stem == compact_folder
    )
    if root_identity_wrapper and blocked_hits:
        folder_identity_hits = {
            term
            for term in blocked_hits
            if term in PROJECT_IDENTITY_START_TERMS and term_matches_name(term, folder.name.lower(), folder_tokens)
        }
        if folder_identity_hits:
            blocked_hits = [term for term in blocked_hits if term not in folder_identity_hits]
            reasons.append("project identity term allowed: " + ", ".join(sorted(folder_identity_hits)))
    if blocked_hits:
        blocked = True
        score -= 250
        reasons.append("blocked start terms: " + ", ".join(sorted(set(blocked_hits))))

    if kind == "npm" and not package_has_start_script(path):
        blocked = True
        score -= 200
        reasons.append("package.json has no scripts.start")

    return LauncherCandidate(str(path), kind, "start", int(score), blocked, reasons)


def score_stop_candidate(path: Path, folder: Path, cfg: Dict[str, Any]) -> LauncherCandidate:
    kind = launcher_kind(path)
    reasons: List[str] = []
    stem_lower = path.stem.lower()
    tokens = tokenize_name(stem_lower)
    stop_terms = [str(item).lower() for item in cfg.get("stop_terms", [])]
    hits = [term for term in stop_terms if term_matches_name(term, stem_lower, tokens)]
    blocked_terms = [str(item).lower() for item in cfg.get("blocked_stop_terms", [])]
    blocked_hits = [term for term in blocked_terms if term_matches_name(term, stem_lower, tokens)]
    if blocked_hits:
        return LauncherCandidate(str(path), kind, "stop", -999, True, ["blocked stop terms: " + ", ".join(sorted(set(blocked_hits)))])
    if not hits:
        return LauncherCandidate(str(path), kind, "stop", -999, True, ["no stop term"])
    score = {"batch": 35, "powershell": 28, "python": 22, "executable": 20, "node": 18}.get(kind, 10)
    reasons.append("stop terms: " + ", ".join(sorted(set(hits))))
    if path.parent == folder:
        score += 20
        reasons.append("bot root")
    if "stop" in hits or "shutdown" in hits or "close" in hits:
        score += 55
    if "emergency" in hits:
        score += 30
        reasons.append("emergency stop")
    if "kill" in hits:
        score += 10
        reasons.append("forceful name")
    unrelated = {
        "build",
        "deploy",
        "install",
        "setup",
        "export",
        "diagnostic",
        "backup",
        "restore",
        "position",
        "positions",
        "order",
        "orders",
        "open_order",
        "active_position",
        "reconcile",
        "reconciliation",
        "post_stop",
        "exit",
    }
    bad = sorted(term for term in unrelated if term_matches_name(term, stem_lower, tokens))
    blocked = bool(bad)
    if bad:
        score -= 180
        reasons.append("conflicting terms: " + ", ".join(bad))
    return LauncherCandidate(str(path), kind, "stop", int(score), blocked, reasons)


def audit_launcher_candidates(folder: Path, cfg: Dict[str, Any]) -> Tuple[List[LauncherCandidate], List[LauncherCandidate]]:
    files = candidate_launcher_files(folder, cfg)
    starts = [score_start_candidate(path, folder, cfg) for path in files]
    stops = [score_stop_candidate(path, folder, cfg) for path in files]
    starts.sort(key=lambda item: (item.blocked, -item.score, item.path.lower()))
    stops = [item for item in stops if item.score > -999]
    stops.sort(key=lambda item: (item.blocked, -item.score, item.path.lower()))
    return starts, stops


def detect_launcher(folder: Path, cfg: Dict[str, Any]) -> Tuple[str, str]:
    """Backward-compatible helper: return only a safe automatic start launcher."""
    starts, _ = audit_launcher_candidates(folder, cfg)
    minimum = int(cfg.get("min_start_score", 60))
    for candidate in starts:
        if not candidate.blocked and candidate.score >= minimum:
            return candidate.path, candidate.kind
    return "", "none"


def detect_stop_launcher(folder: Path, cfg: Dict[str, Any]) -> Tuple[str, str]:
    _, stops = audit_launcher_candidates(folder, cfg)
    minimum = int(cfg.get("min_stop_score", 50))
    for candidate in stops:
        if not candidate.blocked and candidate.score >= minimum:
            return candidate.path, candidate.kind
    return "", "none"


def folder_looks_like_bot(folder: Path, cfg: Dict[str, Any]) -> bool:
    starts, stops = audit_launcher_candidates(folder, cfg)
    if starts or stops:
        return True
    indicators = {"requirements.txt", "pyproject.toml", "package.json", "dockerfile", "docker-compose.yml", "compose.yml"}
    try:
        for item in folder.iterdir():
            if item.is_file() and item.name.lower() in indicators:
                return True
    except Exception:
        return False
    return False


def root_safe_start(folder: Path, cfg: Dict[str, Any]) -> Optional[LauncherCandidate]:
    """Return a safe start candidate located at the project root only."""
    minimum = int(cfg.get("min_start_score", 60))
    starts, _ = audit_launcher_candidates(folder, cfg)
    return next(
        (item for item in starts if not item.blocked and item.score >= minimum and path_depth_relative(folder, Path(item.path).parent) == 0),
        None,
    )


def root_safe_stop(folder: Path, cfg: Dict[str, Any]) -> Optional[LauncherCandidate]:
    minimum = int(cfg.get("min_stop_score", 50))
    _, stops = audit_launcher_candidates(folder, cfg)
    return next(
        (item for item in stops if not item.blocked and item.score >= minimum and path_depth_relative(folder, Path(item.path).parent) == 0),
        None,
    )


def folder_has_project_root_evidence(folder: Path, cfg: Dict[str, Any]) -> bool:
    if root_safe_start(folder, cfg) or root_safe_stop(folder, cfg):
        return True
    indicators = {"requirements.txt", "pyproject.toml", "package.json", "dockerfile", "docker-compose.yml", "compose.yml"}
    try:
        for item in folder.iterdir():
            if item.is_file() and item.name.lower() in indicators:
                return True
    except Exception:
        return False
    return False


def nested_bot_folders(container: Path, cfg: Dict[str, Any]) -> List[Path]:
    """Discover nested runnable project roots inside a collection folder.

    This keeps folders such as C:\\Bots\\Miners from becoming one mixed
    control surface when each child miner has its own launcher/stop files.
    """
    manager_root = app_root()
    max_depth = int(cfg.get("nested_collection_depth", 3))
    found: List[Path] = []
    try:
        for current, dirs, _files in os.walk(container):
            current_path = Path(current)
            dirs[:] = [name for name in dirs if not is_ignored_dir(current_path / name, cfg, manager_root)]
            depth = path_depth_relative(container, current_path)
            if depth <= 0:
                continue
            if depth > max_depth:
                dirs[:] = []
                continue
            if folder_has_project_root_evidence(current_path, cfg):
                found.append(current_path)
                dirs[:] = []
    except Exception as exc:
        log_event(f"Could not scan nested bot folders under {container}: {exc}", "WARNING")
    return found


def candidate_bot_folders(root: Path, cfg: Dict[str, Any]) -> List[Path]:
    if not root.exists():
        return []
    manager_root = app_root()
    candidates: Dict[str, Path] = {}

    def add(path: Path) -> None:
        try:
            key = str(path.resolve()).lower()
        except Exception:
            key = str(path).lower()
        candidates[key] = path

    if cfg.get("scan_immediate_child_folders_only", True):
        try:
            for child in sorted(root.iterdir(), key=lambda path: path.name.lower()):
                if not child.is_dir() or is_ignored_dir(child, cfg, manager_root):
                    continue
                child_has_root = folder_has_project_root_evidence(child, cfg)
                nested = nested_bot_folders(child, cfg) if cfg.get("scan_nested_collections", True) else []
                if child_has_root:
                    add(child)
                elif nested:
                    for nested_child in nested:
                        add(nested_child)
                elif folder_looks_like_bot(child, cfg):
                    # Monitor-only fallback: keep odd legacy projects visible, but
                    # without pretending nested launchers are safe for the parent.
                    add(child)
        except PermissionError:
            log_event(f"Permission denied while scanning {root}", "WARNING")
    else:
        max_depth = int(cfg.get("nested_collection_depth", 3))
        for current, dirs, _files in os.walk(root):
            current_path = Path(current)
            dirs[:] = [name for name in dirs if not is_ignored_dir(current_path / name, cfg, manager_root)]
            if current_path == root:
                continue
            if path_depth_relative(root, current_path) > max_depth:
                dirs[:] = []
                continue
            if folder_has_project_root_evidence(current_path, cfg):
                add(current_path)
                dirs[:] = []
    return sorted(candidates.values(), key=lambda path: str(path).lower())


def classify_bot(folder: Path, launcher_paths: Iterable[str]) -> str:
    text = " ".join([folder.name, *[Path(path).name for path in launcher_paths if path]]).lower()
    compact_text = compact_name(text)
    trade_terms = {
        "trade",
        "trader",
        "spread",
        "perp",
        "futures",
        "exchange",
        "binance",
        "coinbase",
        "kraken",
        "kalshi",
        "polymarket",
        "prediction",
        "market",
        "arbitrage",
        "marketmaker",
        "market_maker",
        "gridbot",
    }
    miner_terms = {"miner", "mining", "ckpool", "hashrate"}
    manager_terms = {"manager", "all_bots", "allbots", "from_manager"}
    utility_terms = {
        "download",
        "downloader",
        "image",
        "movie",
        "video",
        "extractor",
        "chunker",
        "chunk",
        "text",
        "improve",
        "backup",
        "deploy",
        "converter",
        "doctor",
        "netloss",
        "network",
        "diagnostic",
        "diagnostics",
        "tool",
        "utility",
    }
    if any(term in text or term in compact_text for term in manager_terms):
        return "manager"
    if any(term in text for term in trade_terms):
        return "trade"
    if any(term in text for term in miner_terms):
        return "miner"
    if any(term in text or term in compact_text for term in utility_terms):
        return "utility"
    return "unknown"


def _candidate_for_path(candidates: Sequence[LauncherCandidate], path: str) -> Optional[LauncherCandidate]:
    wanted = normalize_text_path(path)
    for candidate in candidates:
        if normalize_text_path(candidate.path) == wanted:
            return candidate
    return None


def _registry_semantic_bots(registry: Dict[str, Any]) -> Dict[str, Any]:
    bots = registry.get("bots", {})
    return bots if isinstance(bots, dict) else {}


def relative_bot_name(root: Path, folder: Path) -> str:
    try:
        parts = folder.resolve().relative_to(root.resolve()).parts
    except Exception:
        parts = folder.parts[-1:]
    if len(parts) <= 1:
        return folder.name
    safe_parts = [re.sub(r"[^A-Za-z0-9_. -]+", "_", part).strip(" _") or "bot" for part in parts]
    return "__".join(safe_parts)


def relative_control_scope(folder: Path, path_text: str) -> str:
    try:
        parts = Path(path_text).resolve().relative_to(folder.resolve()).parts
    except Exception:
        return ""
    if len(parts) <= 1:
        return "<root>"
    return parts[0].lower()


def stop_scope_matches_start(folder: Path, start_path: str, stop_path: str) -> bool:
    if not stop_path:
        return True
    stop_scope = relative_control_scope(folder, stop_path)
    start_scope = relative_control_scope(folder, start_path) if start_path else ""
    if stop_scope == "<root>":
        return True
    if start_scope == "<root>":
        return False
    return bool(start_scope and stop_scope and start_scope == stop_scope)


def scan_bots(cfg: Dict[str, Any], save: bool = True) -> Dict[str, BotRecord]:
    root = Path(str(cfg.get("bots_root", DEFAULT_BOTS_ROOT))).expanduser()
    registry = read_registry()
    existing = _registry_semantic_bots(registry)
    if not root.exists():
        log_event(f"Bots root does not exist; registry was not rewritten: {root}", "WARNING")
        return {name: bot_record_from_dict(name, data) for name, data in sorted(existing.items()) if isinstance(data, dict)}
    found: Dict[str, BotRecord] = {}
    changes: List[str] = []

    for folder in candidate_bot_folders(root, cfg):
        name = relative_bot_name(root, folder)
        old = existing.get(name, {}) if isinstance(existing.get(name), dict) else {}
        starts, stops = audit_launcher_candidates(folder, cfg)
        min_start_score = int(cfg.get("min_start_score", 60))
        min_stop_score = int(cfg.get("min_stop_score", 50))
        safe_auto = next((item for item in starts if not item.blocked and item.score >= min_start_score), None)
        safe_stop = next((item for item in stops if not item.blocked and item.score >= min_stop_score and stop_scope_matches_start(folder, safe_auto.path if safe_auto else "", item.path)), None)

        launcher_manual = bool(old.get("launcher_manual", False))
        launcher_approved = bool(old.get("launcher_approved", False))
        if launcher_manual and old.get("launcher"):
            launcher = str(old.get("launcher", ""))
            candidate = _candidate_for_path(starts, launcher)
            kind = launcher_kind(Path(launcher))
            candidate_blocked = candidate.blocked if candidate else True
            candidate_score = candidate.score if candidate else 0
            launcher_safe = bool(launcher_approved and candidate is not None and not candidate_blocked)
            launcher_reason = "manual selection"
            if candidate is None:
                launcher_reason = "manual launcher is not an audited file inside this bot folder"
            elif candidate_blocked:
                launcher_safe = False
                launcher_reason = "manual launcher now matches a blocked start term"
        else:
            launcher = safe_auto.path if safe_auto else ""
            kind = safe_auto.kind if safe_auto else "none"
            candidate_score = safe_auto.score if safe_auto else 0
            launcher_safe = bool(safe_auto)
            launcher_reason = "; ".join(safe_auto.reasons[:3]) if safe_auto else "no safe automatic start launcher"
            launcher_approved = False

        stop_manual = bool(old.get("stop_launcher_manual", False))
        if stop_manual and old.get("stop_launcher"):
            requested_stop = str(old.get("stop_launcher", ""))
            stop_candidate = _candidate_for_path(stops, requested_stop)
            if stop_candidate is not None and not stop_candidate.blocked and stop_scope_matches_start(folder, launcher, requested_stop):
                stop_launcher = requested_stop
                stop_kind = stop_candidate.kind
            else:
                stop_launcher = ""
                stop_kind = "none"
                stop_manual = False
        else:
            stop_launcher = safe_stop.path if safe_stop else ""
            stop_kind = safe_stop.kind if safe_stop else "none"

        category_manual = bool(old.get("category_manual", False))
        category = str(old.get("category", "unknown")) if category_manual else classify_bot(folder, [launcher, stop_launcher])
        detected_at = str(old.get("detected_at", "")) or utc_stamp()

        try:
            stale_value = float(old["stale_minutes"]) if old.get("stale_minutes") not in (None, "") else None
            if stale_value is not None and (stale_value <= 0 or stale_value > 10080):
                stale_value = None
        except Exception:
            stale_value = None

        rec = BotRecord(
            name=name,
            path=str(folder),
            launcher=launcher,
            launcher_kind=kind,
            launcher_manual=launcher_manual,
            launcher_approved=launcher_approved,
            launcher_safe=launcher_safe,
            launcher_score=int(candidate_score),
            launcher_reason=launcher_reason,
            stop_launcher=stop_launcher,
            stop_launcher_kind=stop_kind,
            stop_launcher_manual=stop_manual,
            heartbeat_file=str(old.get("heartbeat_file", "")),
            heartbeat_manual=bool(old.get("heartbeat_manual", False)),
            stale_minutes=stale_value,
            enabled=bool(old.get("enabled", True)),
            category=category,
            category_manual=category_manual,
            notes=str(old.get("notes", "")),
            detected_at=detected_at,
            # Preserve this field during an unchanged rescan. Updating it on every
            # pass would rewrite the registry and rotate its backup indefinitely.
            last_seen_at=str(old.get("last_seen_at", "")) or utc_stamp(),
        )
        found[name] = rec

        old_launcher = str(old.get("launcher", ""))
        if old and old_launcher != launcher and not launcher_manual:
            changes.append(f"{name}: launcher {Path(old_launcher).name if old_launcher else '--'} -> {Path(launcher).name if launcher else '--'}")

    # Preserve manual/disabled entries only while their folder still exists.
    for name, old in existing.items():
        if name in found or not isinstance(old, dict):
            continue
        old_path = Path(str(old.get("path", "")))
        if old_path.exists() and old_path.is_dir() and (old.get("launcher_manual") or not old.get("enabled", True)):
            found[name] = bot_record_from_dict(name, old)

    found = dict(sorted(found.items(), key=lambda item: item[0].lower()))
    if save:
        registry_newer = schema_newer_than(registry_path(), REGISTRY_VERSION)
        runtime_newer = schema_newer_than(runtime_state_path(), RUNTIME_VERSION)
        if registry_newer is not None:
            log_event(
                f"Scanned {root}; registry schema version {registry_newer} is newer than supported {REGISTRY_VERSION}, so scan results were not written.",
                "WARNING",
            )
            return found
        new_bots = {name: asdict(rec) for name, rec in found.items()}
        changed = new_bots != existing
        if changed or not registry_path().exists():
            registry["bots"] = new_bots
            write_registry(registry)
            detail = f"; {'; '.join(changes[:8])}" if changes else ""
            log_event(f"Scanned {root}; registry updated with {len(found)} folder(s){detail}.")
        else:
            log_event(f"Scanned {root}; no registry changes across {len(found)} folder(s).")
        if runtime_newer is not None:
            log_event(
                f"Runtime state schema version {runtime_newer} is newer than supported {RUNTIME_VERSION}, so orphan ownership pruning was skipped.",
                "WARNING",
            )
        else:
            try:
                prune_runtime_state(set(found))
            except Exception as exc:
                log_event(f"Could not prune orphan runtime ownership: {exc}", "WARNING")
        health_newer = schema_newer_than(health_state_path(), HEALTH_STATE_VERSION)
        if health_newer is not None:
            log_event(
                f"Health state schema version {health_newer} is newer than supported {HEALTH_STATE_VERSION}, so orphan health-history pruning was skipped.",
                "WARNING",
            )
        else:
            try:
                prune_health_state(set(found))
            except Exception as exc:
                log_event(f"Could not prune orphan adaptive health history: {exc}", "WARNING")
    return found


def get_bots(cfg: Dict[str, Any], rescan: bool = False) -> Dict[str, BotRecord]:
    if rescan or not registry_path().exists():
        return scan_bots(cfg, save=True)
    registry = read_registry()
    bots: Dict[str, BotRecord] = {}
    for name, data in _registry_semantic_bots(registry).items():
        if isinstance(data, dict):
            try:
                bots[name] = bot_record_from_dict(name, data)
            except Exception as exc:
                log_event(f"Could not load registry entry {name}: {exc}", "WARNING")
    return dict(sorted(bots.items(), key=lambda item: item[0].lower()))


def parse_process_time(value: Any) -> Optional[float]:
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip().replace("Z", "+00:00")
        parsed = dt.datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.timestamp()
    except Exception:
        return None


def get_windows_processes() -> List[ProcessInfo]:
    ps_command = (
        "$ErrorActionPreference='SilentlyContinue'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        "$items = Get-CimInstance Win32_Process | ForEach-Object { "
        "$created = $null; if ($_.CreationDate) { $created = $_.CreationDate.ToUniversalTime().ToString('o') }; "
        "[PSCustomObject]@{ ProcessId=$_.ProcessId; ParentProcessId=$_.ParentProcessId; Name=$_.Name; "
        "ExecutablePath=$_.ExecutablePath; CommandLine=$_.CommandLine; CreationDate=$created; WorkingSetSize=$_.WorkingSetSize } }; "
        "$items | ConvertTo-Json -Compress -Depth 3"
    )
    for executable in ("powershell.exe", "pwsh.exe"):
        if not shutil.which(executable):
            continue
        try:
            completed = subprocess.run(
                [executable, "-NoProfile", "-NonInteractive", "-Command", ps_command],
                text=True,
                encoding="utf-8-sig",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=25,
            )
            if completed.returncode != 0 or not completed.stdout.strip():
                continue
            raw = json.loads(completed.stdout)
            raw_items = [raw] if isinstance(raw, dict) else raw if isinstance(raw, list) else []
            processes: List[ProcessInfo] = []
            for item in raw_items:
                if not isinstance(item, dict):
                    continue
                try:
                    pid = int(item.get("ProcessId") or 0)
                except Exception:
                    pid = 0
                if pid <= 0:
                    continue
                try:
                    parent_pid = int(item.get("ParentProcessId")) if item.get("ParentProcessId") is not None else None
                except Exception:
                    parent_pid = None
                try:
                    working_set = int(item.get("WorkingSetSize") or 0)
                except Exception:
                    working_set = 0
                processes.append(
                    ProcessInfo(
                        pid=pid,
                        parent_pid=parent_pid,
                        name=str(item.get("Name") or ""),
                        executable_path=str(item.get("ExecutablePath") or ""),
                        command_line=str(item.get("CommandLine") or ""),
                        creation_time=parse_process_time(item.get("CreationDate")),
                        working_set_bytes=working_set,
                    )
                )
            return processes
        except Exception as exc:
            log_event(f"Process scan through {executable} failed: {exc}", "WARNING")
    log_event("No usable PowerShell process scan was available; process status may be incomplete.", "WARNING")
    return []


def get_posix_processes() -> List[ProcessInfo]:
    try:
        completed = subprocess.run(
            ["ps", "-eo", "pid=,ppid=,comm=,args="],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        processes: List[ProcessInfo] = []
        for line in completed.stdout.splitlines():
            parts = line.strip().split(None, 3)
            if len(parts) < 3:
                continue
            processes.append(
                ProcessInfo(
                    pid=int(parts[0]),
                    parent_pid=int(parts[1]),
                    name=parts[2],
                    command_line=parts[3] if len(parts) > 3 else "",
                )
            )
        return processes
    except Exception:
        return []


def get_processes(cfg: Optional[Dict[str, Any]] = None, *, force: bool = False) -> List[ProcessInfo]:
    global _PROCESS_CACHE
    cache_seconds = float((cfg or DEFAULT_CONFIG).get("process_cache_seconds", 2))
    now = time.monotonic()
    if not force and _PROCESS_CACHE[1] and now - _PROCESS_CACHE[0] <= cache_seconds:
        return list(_PROCESS_CACHE[1])
    processes = get_windows_processes() if is_windows_host() else get_posix_processes()
    _PROCESS_CACHE = (now, processes)
    return list(processes)


def process_inventory_reliable(processes: Sequence[ProcessInfo]) -> bool:
    """Return whether process evidence is safe enough for control decisions.

    On Windows the manager's own PID and CreationDate act as a completeness and
    identity probe. An empty/partial CIM result must never erase ownership or
    permit a duplicate bot start merely because no related process was seen.
    """
    if not processes:
        return False
    if not is_windows_host():
        return True
    current = next((process for process in processes if process.pid == os.getpid()), None)
    return bool(current is not None and current.creation_time is not None)


def path_in_process_text(path: str, text: str) -> bool:
    needle = normalize_text_path(path).rstrip("\\")
    haystack = normalize_text_path(text)
    if not needle:
        return False
    start = 0
    allowed_before = set(' \t\r\n"\'=(:,;')
    allowed_after = set('\\/ \t\r\n"\'=:),;&|')
    while True:
        index = haystack.find(needle, start)
        if index < 0:
            return False
        before = haystack[index - 1] if index > 0 else " "
        after_index = index + len(needle)
        after = haystack[after_index] if after_index < len(haystack) else " "
        if before in allowed_before and after in allowed_after:
            return True
        start = index + 1


def distinctive_launcher_name_in_command(launcher: str, command_line: str) -> bool:
    """Allow monitor-only discovery of relative, distinctive launcher names."""
    name = ntpath.basename(str(launcher).replace("/", "\\")).lower().strip()
    if not name or name in GENERIC_LAUNCHER_NAMES or len(name) < 8:
        return False
    command = str(command_line).lower()
    pattern = rf"(?<![a-z0-9_.-]){re.escape(name)}(?![a-z0-9_.-])"
    return re.search(pattern, command) is not None


def is_non_runtime_path_process(process: ProcessInfo) -> bool:
    """Return true for editor/viewer processes that can mention bot paths without running bots."""
    name = (process.name or "").lower().strip()
    return name in NON_RUNTIME_PATH_PROCESS_NAMES


def build_process_maps(processes: Sequence[ProcessInfo]) -> Tuple[Dict[int, ProcessInfo], Dict[int, List[ProcessInfo]]]:
    by_pid = {process.pid: process for process in processes}
    children: Dict[int, List[ProcessInfo]] = {}
    for process in processes:
        if process.parent_pid is not None:
            children.setdefault(process.parent_pid, []).append(process)
    return by_pid, children


def process_ancestor_pids(pid: int, processes: Sequence[ProcessInfo]) -> Set[int]:
    """Return the current process and its visible ancestor chain."""
    by_pid = {process.pid: process for process in processes}
    result: Set[int] = set()
    current = int(pid)
    while current > 0 and current not in result:
        result.add(current)
        process = by_pid.get(current)
        if process is None or process.parent_pid is None:
            break
        current = int(process.parent_pid)
    return result


def process_parent_relation_valid(parent: ProcessInfo, child: ProcessInfo) -> bool:
    if parent.creation_time is not None and child.creation_time is not None:
        return child.creation_time + 2 >= parent.creation_time
    return True


def collect_descendants(root_pids: Iterable[int], processes: Sequence[ProcessInfo]) -> List[ProcessInfo]:
    by_pid, children = build_process_maps(processes)
    result: Dict[int, ProcessInfo] = {}
    queue = list(dict.fromkeys(int(pid) for pid in root_pids))
    while queue:
        pid = queue.pop(0)
        process = by_pid.get(pid)
        if process is None or pid in result:
            continue
        result[pid] = process
        for child in children.get(pid, []):
            if process_parent_relation_valid(process, child):
                queue.append(child.pid)
    return sorted(result.values(), key=lambda item: item.pid)


def root_processes(processes: Sequence[ProcessInfo]) -> List[ProcessInfo]:
    by_pid = {process.pid: process for process in processes}
    roots: List[ProcessInfo] = []
    for process in processes:
        parent = by_pid.get(process.parent_pid or -1)
        if parent is None or not process_parent_relation_valid(parent, process):
            roots.append(process)
    return sorted(roots, key=lambda item: ((item.creation_time or 0), item.pid))


def runtime_entry_for_bot(state: Dict[str, Any], bot_name: str) -> Dict[str, Any]:
    bots = state.setdefault("bots", {})
    entry = bots.get(bot_name, {})
    if not isinstance(entry, dict):
        entry = {}
        bots[bot_name] = entry
    entry.setdefault("roots", [])
    return entry


def clear_runtime_bot(bot_name: str) -> None:
    state = read_runtime_state()
    bots = state.setdefault("bots", {})
    if bot_name in bots:
        del bots[bot_name]
        write_runtime_state(state)


def launcher_fingerprint(bot: BotRecord) -> str:
    payload = f"{normalize_text_path(bot.path)}|{normalize_text_path(bot.launcher)}|{bot.launcher_kind}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record_runtime_roots(bot: BotRecord, roots: Sequence[ProcessInfo], started_at: float) -> None:
    unique = {process.pid: process for process in roots}
    state = read_runtime_state()
    entry = runtime_entry_for_bot(state, bot.name)
    entry.update(
        {
            "launcher": bot.launcher,
            "launcher_fingerprint": launcher_fingerprint(bot),
            "started_at_epoch": started_at,
            "started_at": dt.datetime.fromtimestamp(started_at, dt.timezone.utc).isoformat(timespec="seconds"),
            "roots": [
                {
                    "pid": process.pid,
                    "created_at_epoch": process.creation_time,
                    "name": process.name,
                }
                for process in sorted(unique.values(), key=lambda item: item.pid)
            ],
        }
    )
    write_runtime_state(state)


def managed_tracking(bot: BotRecord, processes: Sequence[ProcessInfo]) -> Tuple[List[ProcessInfo], List[ProcessInfo], bool]:
    state = read_runtime_state()
    entry = state.get("bots", {}).get(bot.name, {}) if isinstance(state.get("bots"), dict) else {}
    roots_raw = entry.get("roots", []) if isinstance(entry, dict) else []
    if not isinstance(roots_raw, list) or not roots_raw:
        return [], [], False
    by_pid = {process.pid: process for process in processes}
    valid_roots: List[ProcessInfo] = []
    stale_found = False
    expected_fingerprint = str(entry.get("launcher_fingerprint", "")) if isinstance(entry, dict) else ""
    if expected_fingerprint and expected_fingerprint != launcher_fingerprint(bot):
        # A profile/launcher change invalidates old control ownership.
        stale_found = True
        return [], [], stale_found
    for raw in roots_raw:
        if not isinstance(raw, dict):
            stale_found = True
            continue
        try:
            pid = int(raw.get("pid") or 0)
        except Exception:
            stale_found = True
            continue
        process = by_pid.get(pid)
        if process is None:
            stale_found = True
            continue
        expected_created = parse_process_time(raw.get("created_at_epoch"))
        if expected_created is None or process.creation_time is None:
            stale_found = True
            continue
        if abs(expected_created - process.creation_time) > 4:
            stale_found = True
            continue
        valid_roots.append(process)
    managed = collect_descendants([process.pid for process in valid_roots], processes)
    return managed, valid_roots, stale_found


def observed_tracking(bot: BotRecord, processes: Sequence[ProcessInfo]) -> Tuple[List[ProcessInfo], List[ProcessInfo], str, List[str]]:
    matches: List[ProcessInfo] = []
    reasons: List[str] = []
    high_pids: Set[int] = set()
    manager_path = normalize_text_path(str(app_root()))
    manager_processes = process_ancestor_pids(os.getpid(), processes)
    for process in processes:
        if process.pid in manager_processes:
            continue
        text = process.searchable_text
        if manager_path and manager_path in text:
            continue
        launcher_match = bool(bot.launcher and path_in_process_text(bot.launcher, text))
        bot_path_match = bool(bot.path and path_in_process_text(bot.path, text))
        launcher_name_match = bool(
            bot.launcher and distinctive_launcher_name_in_command(bot.launcher, process.command_line)
        )
        executable_match = bool(
            bot.launcher
            and Path(bot.launcher).suffix.lower() == ".exe"
            and normalize_text_path(process.executable_path) == normalize_text_path(bot.launcher)
        )
        if is_non_runtime_path_process(process) and (launcher_match or launcher_name_match or bot_path_match):
            reasons.append(f"PID {process.pid}: ignored non-runtime viewer/editor path reference")
            continue
        if launcher_match or executable_match:
            matches.append(process)
            high_pids.add(process.pid)
            reasons.append(f"PID {process.pid}: exact launcher")
        elif launcher_name_match:
            matches.append(process)
            reasons.append(f"PID {process.pid}: distinctive launcher filename")
        elif bot_path_match:
            matches.append(process)
            reasons.append(f"PID {process.pid}: bot path")
    unique = sorted({process.pid: process for process in matches}.values(), key=lambda item: item.pid)
    roots = root_processes(unique)
    if roots:
        expanded = collect_descendants([process.pid for process in roots], processes)
        manager_processes = process_ancestor_pids(os.getpid(), processes)
        unique = [process for process in expanded if process.pid not in manager_processes]
    confidence = "HIGH" if high_pids else "MEDIUM" if unique else "NONE"
    return unique, roots, confidence, reasons


def track_bot(bot: BotRecord, processes: Sequence[ProcessInfo], *, cleanup_stale: bool = True) -> TrackingResult:
    managed, managed_roots, stale = managed_tracking(bot, processes)
    inventory_reliable = process_inventory_reliable(processes)
    if stale and cleanup_stale and inventory_reliable:
        state = read_runtime_state()
        bots = state.setdefault("bots", {})
        if bot.name in bots:
            if managed_roots:
                entry = runtime_entry_for_bot(state, bot.name)
                entry["roots"] = [
                    {"pid": process.pid, "created_at_epoch": process.creation_time, "name": process.name}
                    for process in managed_roots
                ]
            else:
                del bots[bot.name]
            try:
                write_runtime_state(state)
            except Exception as exc:
                log_event(f"Could not clean stale runtime state for {bot.name}: {exc}", "WARNING")
    observed, observed_roots, confidence, reasons = observed_tracking(bot, processes)
    if managed:
        managed_pids = {process.pid for process in managed}
        observed = [process for process in observed if process.pid not in managed_pids]
        observed_roots = root_processes(observed)
        if not observed:
            confidence = "NONE"
    return TrackingResult(managed, managed_roots, observed, observed_roots, confidence, reasons)


def related_processes(bot: BotRecord, processes: Sequence[ProcessInfo]) -> List[ProcessInfo]:
    """Compatibility helper; monitoring may include managed plus observed processes."""
    tracking = track_bot(bot, processes, cleanup_stale=False)
    combined = {process.pid: process for process in tracking.managed_processes + tracking.observed_processes}
    return sorted(combined.values(), key=lambda item: item.pid)


def health_candidate_family(path: Path, bot_path: Path) -> str:
    """Return a stable key across rotations and common sharded latest logs."""
    try:
        relative = path.relative_to(bot_path)
    except Exception:
        relative = Path(path.name)
    raw_stem = path.stem.lower()
    rolling_alias = bool(re.search(r"(?:[_\-.](?:latest|current|new))+$", raw_stem))
    stem = re.sub(
        r"(?<!\d)20\d{2}[-_]\d{2}[-_]\d{2}(?:[t_-]\d{2}[-_]?\d{2}[-_]?\d{2}z?)?(?!\d)",
        "<stamp>",
        raw_stem,
    )
    stem = re.sub(r"(?<!\d)20\d{6}(?:[_-]?\d{6})?(?!\d)", "<stamp>", stem)
    stem = re.sub(r"(?:[_\-.](?:latest|current|new))+$", "", stem)
    stem = re.sub(r"[_\-.]+", "_", stem).strip("_") or raw_stem
    parent = relative.parent.as_posix().lower().strip("./")
    runtime_tokens = {"log", "logs", "runtime", "telemetry", "heartbeat", "heartbeats"}
    runtime_parent = any(
        tokenize_name(part).intersection(runtime_tokens)
        for part in relative.parent.parts
    )
    # Multi-worker and multi-market bots commonly expose one *_latest.log per
    # shard. Newest-file selection can hop between those files every refresh.
    # Treat that sibling set as one aggregate progress family so continuity and
    # cadence learning survive the hop. This does not hide a stuck shard: the
    # previous model already treated any freshest shard as whole-bot progress.
    if rolling_alias and parent and runtime_parent:
        return f"{parent}/<rolling-latest>{path.suffix.lower()}"
    filename = f"{stem}{path.suffix.lower()}"
    return f"{parent}/{filename}" if parent else filename


def health_excluded_directory_terms(path: Path, bot_path: Path, cfg: Dict[str, Any]) -> List[str]:
    try:
        directory_parts = path.relative_to(bot_path).parts[:-1]
    except Exception:
        directory_parts = path.parts[:-1]
    configured = [str(item).lower().strip() for item in cfg.get("health_excluded_path_terms", [])]
    matches: Set[str] = set()
    for part in directory_parts:
        stem = str(part).lower()
        tokens = tokenize_name(stem)
        for term in configured:
            if term_matches_name(term, stem, tokens):
                matches.add(term)
    return sorted(matches)


def is_runtime_log_directory(relative_parts: Sequence[str], cfg: Dict[str, Any]) -> bool:
    common_dirs = {str(item).lower() for item in cfg.get("log_dir_names", [])}
    runtime_tokens = {"log", "logs", "runtime", "telemetry", "heartbeat", "heartbeats"}
    for part in relative_parts:
        lowered = str(part).lower()
        if lowered in common_dirs or tokenize_name(lowered).intersection(runtime_tokens):
            return True
    return False


def parse_health_contract_timestamp(value: Any) -> Optional[float]:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except Exception:
        return None
    if parsed.tzinfo is None:
        return None
    try:
        return parsed.timestamp()
    except Exception:
        return None


def contract_nonnegative_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except Exception:
        return None
    return parsed if parsed >= 0 else None


def health_contract_candidate(path: Path, bot_path: Path, cfg: Dict[str, Any], *, now: Optional[float] = None) -> LogCandidate:
    """Read one bounded, local, optional BotOps health contract.

    The file is monitoring evidence only. It never grants process-control rights
    and never causes an automatic start, stop, restart, adoption, or force-stop.
    File mtime remains the freshness clock; the embedded timestamp is checked for
    consistency and clock skew rather than trusted as a control authority.
    """
    now_value = time.time() if now is None else float(now)
    reasons = ["structured BotOps health contract"]
    errors: List[str] = []
    stat = safe_stat(path)
    mtime = stat.st_mtime if stat else None
    family = "contract/" + path.name.lower()
    try:
        relative = path.relative_to(bot_path).as_posix().lower()
        family = "contract/" + relative
    except Exception:
        pass

    def result(**kwargs: Any) -> LogCandidate:
        reliable = not errors
        return LogCandidate(
            str(path),
            180 if reliable else -180,
            reliable,
            mtime,
            reasons,
            tier="contract" if reliable else "none",
            family=family,
            evidence_kind="contract",
            contract_errors=list(errors),
            **kwargs,
        )

    if stat is None:
        errors.append("contract could not be stat-ed")
        return result()
    if path.is_symlink():
        errors.append("contract symlinks are not trusted")
        return result()
    if not is_path_within(path, bot_path):
        errors.append("contract is outside the bot folder")
        return result()
    maximum = max(1024, int(cfg.get("health_contract_max_bytes", 65536)))
    if stat.st_size > maximum:
        errors.append(f"contract exceeds {maximum} byte limit")
        return result()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append("contract JSON is unreadable: " + redact(str(exc)))
        return result()
    if not isinstance(payload, dict):
        errors.append("contract root must be a JSON object")
        return result()

    schema = str(payload.get("schema", "")).strip()
    state = str(payload.get("state", "")).strip().lower()
    updated_at = str(payload.get("updated_at", "")).strip()
    updated_epoch = parse_health_contract_timestamp(updated_at)
    if schema != HEALTH_CONTRACT_SCHEMA:
        errors.append(f"schema must be {HEALTH_CONTRACT_SCHEMA}")
    if state not in HEALTH_CONTRACT_STATES:
        errors.append("state must be starting, ready, degraded, stopping, stopped, or failed")
    if updated_epoch is None:
        errors.append("updated_at must be timezone-aware ISO-8601")

    default_live = state not in {"stopped", "failed"}
    default_ready = state == "ready"
    live_raw = payload.get("live", default_live)
    ready_raw = payload.get("ready", default_ready)
    if not isinstance(live_raw, bool):
        errors.append("live must be a boolean when present")
        live = default_live
    else:
        live = live_raw
    if not isinstance(ready_raw, bool):
        errors.append("ready must be a boolean when present")
        ready = default_ready
    else:
        ready = ready_raw

    pid_raw = payload.get("pid")
    pid = contract_nonnegative_int(pid_raw)
    if pid_raw is not None and (pid is None or pid <= 0):
        errors.append("pid must be a positive integer when present")
        pid = None
    started_raw = payload.get("process_started_at_epoch")
    started = finite_float(started_raw)
    if started_raw is not None and (started is None or started <= 0):
        errors.append("process_started_at_epoch must be a positive finite number when present")
        started = None
    heartbeat_raw = payload.get("heartbeat_sequence")
    heartbeat_sequence = contract_nonnegative_int(heartbeat_raw)
    if heartbeat_raw is not None and heartbeat_sequence is None:
        errors.append("heartbeat_sequence must be a non-negative integer when present")
    progress_raw = payload.get("progress_sequence")
    progress_sequence = contract_nonnegative_int(progress_raw)
    if progress_raw is not None and progress_sequence is None:
        errors.append("progress_sequence must be a non-negative integer when present")

    message = str(payload.get("message", "") or "").replace("\r", " ").replace("\n", " ").strip()[:240]
    version = str(payload.get("version", "") or "").strip()[:80]
    timestamp_skew = bool(
        updated_epoch is not None
        and updated_epoch > now_value + max(0.0, float(cfg.get("health_future_skew_seconds", 120)))
    )
    if timestamp_skew:
        reasons.append("embedded updated_at is ahead of the local clock")
    if updated_epoch is not None and mtime is not None:
        drift = abs(updated_epoch - mtime)
        allowed_drift = max(300.0, float(cfg.get("health_future_skew_seconds", 120)) * 2.0)
        if drift > allowed_drift:
            reasons.append(f"embedded timestamp differs from file mtime by {int(drift)} seconds")

    return result(
        contract_schema=schema,
        contract_state=state,
        contract_live=live,
        contract_ready=ready,
        contract_pid=pid,
        contract_process_started_at_epoch=started,
        contract_heartbeat_sequence=heartbeat_sequence,
        contract_progress_sequence=progress_sequence,
        contract_updated_at=updated_at,
        contract_updated_at_epoch=updated_epoch,
        contract_timestamp_skew=timestamp_skew,
        contract_message=message,
        contract_version=version,
    )


def contract_identity_match(candidate: Optional[LogCandidate], processes: Sequence[ProcessInfo]) -> Optional[bool]:
    if candidate is None or candidate.evidence_kind != "contract" or candidate.contract_pid is None:
        return None
    process = next((item for item in processes if item.pid == candidate.contract_pid), None)
    if process is None:
        return False
    expected_started = candidate.contract_process_started_at_epoch
    if expected_started is not None and process.creation_time is not None:
        return abs(float(expected_started) - float(process.creation_time)) <= 4.0
    return True


def score_log_candidate(path: Path, bot_path: Path, cfg: Dict[str, Any]) -> LogCandidate:
    reasons: List[str] = []
    score = {".log": 40, ".jsonl": 30, ".csv": 15, ".txt": 5}.get(path.suffix.lower(), 0)
    reasons.append(f"{path.suffix.lower()} file")
    relative_parts: Tuple[str, ...]
    try:
        relative_parts = tuple(part.lower() for part in path.relative_to(bot_path).parts[:-1])
    except Exception:
        relative_parts = tuple(part.lower() for part in path.parts[:-1])
    runtime_directory = is_runtime_log_directory(relative_parts, cfg)
    if runtime_directory:
        score += 25
        reasons.append("log/runtime directory")
    if any(part in {"docs", "doc", "documentation", "examples", "example", "tests", "test"} for part in relative_parts):
        score -= 50
        reasons.append("documentation/test directory")

    stem = path.stem.lower()
    tokens = tokenize_name(stem)
    positive = [
        term
        for term in (str(item).lower() for item in cfg.get("log_positive_terms", []))
        if term_matches_name(term, stem, tokens)
    ]
    negative = [
        term
        for term in (str(item).lower() for item in cfg.get("log_negative_terms", []))
        if term_matches_name(term, stem, tokens)
    ]
    if positive:
        score += min(36, 10 + 6 * (len(set(positive)) - 1))
        reasons.append("operational terms: " + ", ".join(sorted(set(positive))))
    if negative:
        score -= 60 * len(set(negative))
        reasons.append("non-runtime terms: " + ", ".join(sorted(set(negative))))
    excluded_terms = health_excluded_directory_terms(path, bot_path, cfg)
    if excluded_terms:
        score -= 140
        reasons.append("excluded non-runtime directory terms: " + ", ".join(excluded_terms))
    stat = safe_stat(path)
    minimum = int(cfg.get("log_min_score", 35))
    reliable = score >= minimum and not excluded_terms
    tier = "strong" if reliable and (score >= max(60, minimum + 20) or runtime_directory) else "standard" if reliable else "none"
    return LogCandidate(
        str(path),
        int(score),
        reliable,
        stat.st_mtime if stat else None,
        reasons,
        tier=tier,
        family=health_candidate_family(path, bot_path),
    )


def find_log_candidates(bot_path: Path, cfg: Dict[str, Any], *, force: bool = False) -> List[LogCandidate]:
    cache_key = normalize_text_path(str(bot_path))
    cache_now = time.monotonic()
    wall_now = time.time()
    cache_seconds = float(cfg.get("log_cache_seconds", 5))
    cached = _LOG_CANDIDATE_CACHE.get(cache_key)
    if not force and cached and cache_now - cached[0] <= cache_seconds:
        return list(cached[1])

    extensions = {str(item).lower() for item in cfg.get("log_extensions", [])}
    max_files = int(cfg.get("max_log_search_files_per_bot", 350))
    max_depth = int(cfg.get("log_search_depth", 4))
    manager_root = app_root()
    found: Dict[str, Path] = {}
    if bot_path.exists():
        try:
            for current, dirs, filenames in os.walk(bot_path):
                current_path = Path(current)
                dirs[:] = [name for name in dirs if not is_ignored_dir(current_path / name, cfg, manager_root)]
                if path_depth_relative(bot_path, current_path) > max_depth:
                    dirs[:] = []
                    continue
                for filename in filenames:
                    path = current_path / filename
                    if path.suffix.lower() in extensions and is_path_within(path, bot_path):
                        found[str(path).lower()] = path
                        if len(found) >= max_files:
                            break
                if len(found) >= max_files:
                    break
        except Exception:
            pass
    contract_candidates: List[LogCandidate] = []
    if bot_path.exists():
        for relative in HEALTH_CONTRACT_RELATIVE_PATHS:
            contract_path = bot_path / Path(relative)
            if contract_path.exists() and contract_path.is_file():
                contract_candidates.append(health_contract_candidate(contract_path, bot_path, cfg, now=wall_now))
    candidates = contract_candidates + [score_log_candidate(path, bot_path, cfg) for path in found.values()]
    candidates.sort(key=lambda item: (-item.score, -(item.mtime or 0), item.path.lower()))
    _LOG_CANDIDATE_CACHE[cache_key] = (cache_now, candidates)
    return list(candidates)


def is_path_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


def select_health_candidate(
    bot: BotRecord,
    cfg: Dict[str, Any],
    *,
    now: Optional[float] = None,
    candidates: Optional[Sequence[LogCandidate]] = None,
) -> Optional[LogCandidate]:
    bot_path = Path(bot.path)
    now_value = time.time() if now is None else float(now)
    if bot.heartbeat_manual and bot.heartbeat_file:
        path = Path(bot.heartbeat_file)
        if path.exists() and path.is_file() and is_path_within(path, bot_path):
            stat = safe_stat(path)
            if stat is None:
                return None
            return LogCandidate(
                str(path),
                999,
                True,
                stat.st_mtime,
                ["manual heartbeat selection"],
                tier="manual",
                family=health_candidate_family(path, bot_path),
            )
    source_candidates = list(candidates) if candidates is not None else find_log_candidates(bot_path, cfg)
    reliable = [
        candidate
        for candidate in source_candidates
        if candidate.reliable and candidate.mtime is not None
    ]
    if not reliable:
        return None
    allowed_future = float(cfg.get("health_future_skew_seconds", 120))
    plausible = [candidate for candidate in reliable if candidate.mtime is None or candidate.mtime <= now_value + allowed_future]
    pool = plausible or reliable
    tier_rank = {"manual": 4, "contract": 3, "strong": 2, "standard": 1, "none": 0}
    timestamped = [candidate.mtime for candidate in pool if candidate.mtime is not None]
    if timestamped:
        freshest = max(timestamped)
        try:
            trust_window = max(
                60.0,
                float(bot.stale_minutes if bot.stale_minutes is not None else cfg.get("stale_minutes", 10)) * 60.0,
            )
        except Exception:
            trust_window = float(DEFAULT_CONFIG["stale_minutes"]) * 60.0
        # Prefer stronger provenance when it is still within one fixed health
        # window of the freshest candidate. A weak file cannot steal selection
        # by seconds, while a genuinely current standard source can replace a
        # strong source that has fallen outside the expected progress window.
        near_freshest = [
            candidate
            for candidate in pool
            if candidate.mtime is not None and candidate.mtime >= freshest - trust_window
        ]
        if near_freshest:
            pool = near_freshest
    pool.sort(
        key=lambda item: (
            -tier_rank.get(item.tier, 0),
            -(item.mtime or 0),
            -item.score,
            item.path.lower(),
        )
    )
    return pool[0]


def finite_float(value: Any) -> Optional[float]:
    try:
        parsed = float(value)
    except Exception:
        return None
    return parsed if math.isfinite(parsed) else None


def health_bot_identity(bot: BotRecord) -> str:
    normalized = normalize_text_path(bot.path).rstrip("\\/")
    return hashlib.sha256(normalized.encode("utf-8", errors="replace")).hexdigest()[:16]


def health_percentile(values: Sequence[float], fraction: float) -> Optional[float]:
    clean = sorted(value for value in values if math.isfinite(value) and value > 0)
    if not clean:
        return None
    if len(clean) == 1:
        return clean[0]
    position = max(0.0, min(1.0, float(fraction))) * (len(clean) - 1)
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return clean[lower]
    weight = position - lower
    return clean[lower] * (1.0 - weight) + clean[upper] * weight


def robust_health_interval(values: Sequence[float]) -> Tuple[Optional[float], Optional[float]]:
    """Return robust expected interval and spread in seconds.

    The upper-tail estimate is clipped against median absolute deviation so a
    single pause cannot permanently teach the monitor that a hung bot is normal.
    """
    clean = [value for value in values if math.isfinite(value) and value > 0]
    if not clean:
        return None, None
    median = float(statistics.median(clean))
    deviations = [abs(value - median) for value in clean]
    mad = float(statistics.median(deviations)) if deviations else 0.0
    robust_spread = max(HEALTH_MIN_STDDEV_SECONDS, 1.4826 * mad)
    upper_tail = health_percentile(clean, 0.90) or median
    robust_cap = median + 4.0 * robust_spread
    expected = max(median, min(upper_tail, robust_cap))
    return expected, robust_spread


def health_accrual_suspicion(age_seconds: Optional[float], values: Sequence[float]) -> Optional[float]:
    """Return a bounded phi-like suspicion score from observed update intervals.

    This is diagnostic evidence, not an automatic restart trigger. File mtimes
    are less precise than network heartbeats, so the model deliberately carries
    a minimum variance and an acceptable-pause allowance.
    """
    if age_seconds is None:
        return None
    clean = [value for value in values if math.isfinite(value) and value > 0]
    if len(clean) < 3:
        return None
    mean = float(statistics.fmean(clean))
    observed_std = float(statistics.pstdev(clean)) if len(clean) > 1 else 0.0
    stddev = max(HEALTH_MIN_STDDEV_SECONDS, mean * 0.10, observed_std)
    adjusted_age = max(0.0, float(age_seconds) - HEALTH_ACCEPTABLE_PAUSE_SECONDS)
    z_score = (adjusted_age - mean) / stddev
    survival = 0.5 * math.erfc(z_score / math.sqrt(2.0))
    return min(16.0, max(0.0, -math.log10(max(1e-16, survival))))


def assess_health_evidence(
    bot: BotRecord,
    candidate: Optional[LogCandidate],
    cfg: Dict[str, Any],
    health_state: Dict[str, Any],
    *,
    now: float,
    active: bool,
    suppress_stale: bool = False,
) -> HealthAssessment:
    """Evaluate and learn operational progress without taking control actions.

    Learning is based only on continuously observed mtime advances from the same
    evidence family. Gaps while BotOps is closed, process downtime, rotations to
    a different evidence family, clock skew, and mtime regressions do not become
    cadence samples.
    """
    try:
        static_threshold_minutes = max(
            0.0,
            float(bot.stale_minutes if bot.stale_minutes is not None else cfg.get("stale_minutes", 10)),
        )
    except Exception:
        static_threshold_minutes = max(0.0, float(DEFAULT_CONFIG["stale_minutes"]))
    static_threshold_seconds = max(1.0, static_threshold_minutes * 60.0)
    continuity_limit = max(60.0, float(cfg.get("watch_interval_seconds", 10)) * 3.0)
    future_skew_seconds = max(0.0, float(cfg.get("health_future_skew_seconds", 120)))
    max_sample_seconds = 7.0 * 24.0 * 3600.0
    notes: List[str] = []

    bots_state = health_state.setdefault("bots", {})
    if not isinstance(bots_state, dict):
        bots_state = {}
        health_state["bots"] = bots_state
    raw_entry = bots_state.get(bot.name, {})
    entry_existed = isinstance(raw_entry, dict) and bool(raw_entry)
    entry = copy.deepcopy(raw_entry) if isinstance(raw_entry, dict) else {}
    before = json.dumps(entry, sort_keys=True, default=str)

    intervals: List[float] = []
    raw_intervals = entry.get("intervals_seconds", [])
    if isinstance(raw_intervals, list):
        for value in raw_intervals:
            parsed = finite_float(value)
            if parsed is not None and 0 < parsed <= max_sample_seconds:
                intervals.append(parsed)
    intervals = intervals[-HEALTH_SAMPLE_WINDOW:]

    current_bot_identity = health_bot_identity(bot)
    previous_bot_identity = str(entry.get("bot_identity", "") or "")
    identity_changed = bool(previous_bot_identity and previous_bot_identity != current_bot_identity)
    if identity_changed:
        intervals = []
        entry = {}
        entry["continuous_since"] = now
        notes.append("bot path identity changed; adaptive health history reset")

    previous_family = str(entry.get("family", "") or "")
    current_family = str(candidate.family if candidate else "")
    family_changed = bool(candidate and previous_family and current_family != previous_family)
    first_family = bool(candidate and not previous_family)
    if family_changed:
        intervals = []
        entry["consecutive_suspect"] = 0
        entry.pop("last_suspect_counted_at", None)
        entry["continuous_since"] = now
        notes.append("health evidence family changed; cadence learning restarted")

    previous_observed_at = finite_float(entry.get("last_observed_at"))
    previous_active = bool(entry.get("active_last_observation", False))
    observation_gap = now - previous_observed_at if previous_observed_at is not None else None
    continuous_observation = bool(
        previous_active
        and observation_gap is not None
        and 0.0 <= observation_gap <= continuity_limit
        and not family_changed
        and not identity_changed
    )
    if active and candidate and not continuous_observation and not first_family and previous_observed_at is not None:
        notes.append("monitoring continuity reset; skipped cross-gap cadence sample")

    mtime = finite_float(candidate.mtime) if candidate else None
    clock_skew = bool((mtime is not None and mtime > now + future_skew_seconds) or (candidate is not None and candidate.contract_timestamp_skew))
    age_seconds = None if mtime is None or clock_skew else max(0.0, now - mtime)
    advanced = False

    if candidate is None or mtime is None:
        # Make the next real observation establish a baseline rather than
        # learning across a period with no trustworthy evidence.
        entry["active_last_observation"] = False
        entry["consecutive_suspect"] = 0
        entry.pop("last_suspect_counted_at", None)
    elif clock_skew:
        entry["last_mtime"] = mtime
        entry["active_last_observation"] = False
        entry["consecutive_suspect"] = 0
        entry.pop("last_suspect_counted_at", None)
        entry["continuous_since"] = now
        notes.append("selected evidence timestamp is ahead of the local clock")
    elif not active:
        # Preserve learned cadence, but never bridge process downtime with a
        # synthetic interval when the bot later starts.
        entry["last_mtime"] = mtime
        entry["active_last_observation"] = False
        entry["consecutive_suspect"] = 0
        entry.pop("last_suspect_counted_at", None)
        entry["continuous_since"] = now
    elif family_changed or first_family or not continuous_observation:
        entry["last_mtime"] = mtime
        entry["last_advance_seen_at"] = now
        entry["active_last_observation"] = True
        entry["consecutive_suspect"] = 0
        entry.pop("last_suspect_counted_at", None)
        entry["continuous_since"] = now
    else:
        previous_mtime = finite_float(entry.get("last_mtime"))
        if previous_mtime is None:
            entry["last_mtime"] = mtime
            entry["last_advance_seen_at"] = now
        elif mtime > previous_mtime + 0.001:
            interval = mtime - previous_mtime
            if 0 < interval <= max_sample_seconds:
                intervals.append(interval)
                intervals = intervals[-HEALTH_SAMPLE_WINDOW:]
                advanced = True
            else:
                notes.append("mtime advance was outside the bounded learning window")
            entry["last_mtime"] = mtime
            entry["last_advance_seen_at"] = now
            entry["consecutive_suspect"] = 0
            entry.pop("last_suspect_counted_at", None)
        elif mtime < previous_mtime - 1.0:
            # Replacement, restore, or a source clock correction invalidates the
            # learned sequence for this evidence family.
            intervals = []
            entry["last_mtime"] = mtime
            entry["last_advance_seen_at"] = now
            entry["continuous_since"] = now
            entry["consecutive_suspect"] = 0
            entry.pop("last_suspect_counted_at", None)
            notes.append("health mtime regressed; cadence history reset")
        entry["active_last_observation"] = True

    minimum_samples = max(3, int(cfg.get("adaptive_health_min_samples", 5)))
    expected_interval, robust_spread = robust_health_interval(intervals)
    adaptive_ready = bool(
        cfg.get("adaptive_health_enabled", True)
        and len(intervals) >= minimum_samples
        and expected_interval is not None
    )
    learned_threshold_seconds: Optional[float] = None
    if adaptive_ready and expected_interval is not None:
        spread_allowance = max(
            HEALTH_ACCEPTABLE_PAUSE_SECONDS,
            2.0 * float(robust_spread or HEALTH_MIN_STDDEV_SECONDS),
        )
        learned_threshold_seconds = expected_interval * HEALTH_INTERVAL_MULTIPLIER + spread_allowance
        maximum = static_threshold_seconds * max(
            1.0,
            float(cfg.get("adaptive_health_max_threshold_factor", 6.0)),
        )
        effective_threshold_seconds = max(
            static_threshold_seconds,
            min(maximum, learned_threshold_seconds),
        )
        mode = "adaptive"
    else:
        effective_threshold_seconds = static_threshold_seconds
        mode = "fixed"

    suspicion = health_accrual_suspicion(age_seconds, intervals)
    suspect = bool(
        active
        and candidate is not None
        and age_seconds is not None
        and not clock_skew
        and not suppress_stale
        and age_seconds > effective_threshold_seconds
    )
    previous_suspect_count = max(0, int(finite_float(entry.get("consecutive_suspect")) or 0))
    confirmation_spacing_seconds = max(
        1.0,
        min(60.0, float(cfg.get("watch_interval_seconds", 10))),
    )
    last_suspect_counted_at = finite_float(entry.get("last_suspect_counted_at"))
    if suspect:
        countable_observation = bool(
            previous_suspect_count == 0
            or last_suspect_counted_at is None
            or now < last_suspect_counted_at
            or now - last_suspect_counted_at >= confirmation_spacing_seconds
        )
        if countable_observation:
            consecutive_suspect = previous_suspect_count + 1
            entry["last_suspect_counted_at"] = now
        else:
            consecutive_suspect = previous_suspect_count
            notes.append("rapid duplicate suspect observation was debounced")
    else:
        consecutive_suspect = 0
        entry.pop("last_suspect_counted_at", None)
    confirmations = max(1, int(cfg.get("health_stale_confirmations", 2)))
    hard_factor = max(1.0, float(cfg.get("health_hard_stale_factor", 2.0)))
    hard_overdue = bool(
        suspect
        and age_seconds is not None
        and age_seconds >= effective_threshold_seconds * hard_factor
    )
    stale_confirmed = bool(suspect and (consecutive_suspect >= confirmations or hard_overdue))

    can_learn = bool(active and candidate is not None and mtime is not None and not clock_skew)
    if not can_learn:
        # No cadence state is needed for an inactive bot, a missing timestamp,
        # or clock-skewed evidence. If a prior active record exists, only break
        # continuity once; repeated STOPPED/NO_HEARTBEAT refreshes stay read-only.
        if entry_existed:
            persisted_entry = {} if identity_changed else copy.deepcopy(raw_entry)
            persisted_entry["bot_identity"] = current_bot_identity
            persisted_entry["active_last_observation"] = False
            persisted_entry["consecutive_suspect"] = 0
            persisted_entry.pop("last_suspect_counted_at", None)
            if candidate is not None and mtime is not None and (family_changed or identity_changed):
                persisted_entry.update(
                    {
                        "family": current_family,
                        "selected_path": candidate.path,
                        "selected_tier": candidate.tier,
                        "selected_score": candidate.score,
                        "last_mtime": mtime,
                        "intervals_seconds": [],
                        "mode": "fixed",
                    }
                )
            bots_state[bot.name] = persisted_entry
            after = json.dumps(persisted_entry, sort_keys=True, default=str)
        else:
            bots_state.pop(bot.name, None)
            after = before
        return HealthAssessment(
            age_minutes=(age_seconds / 60.0) if age_seconds is not None else None,
            static_threshold_minutes=static_threshold_seconds / 60.0,
            effective_threshold_minutes=effective_threshold_seconds / 60.0,
            mode=mode,
            suspicion=suspicion,
            sample_count=len(intervals),
            advanced=False,
            clock_skew=clock_skew,
            suspect=suspect,
            stale_confirmed=stale_confirmed,
            consecutive_suspect=consecutive_suspect,
            learned_interval_seconds=expected_interval,
            state_changed=before != after,
            notes=notes,
        )

    entry["bot_identity"] = current_bot_identity
    if candidate:
        entry["family"] = current_family
        entry["selected_path"] = candidate.path
        entry["selected_tier"] = candidate.tier
        entry["selected_score"] = candidate.score
    else:
        entry["selected_path"] = ""
        entry["selected_tier"] = "none"
        entry["selected_score"] = 0
    entry["last_observed_at"] = now
    entry["active_last_observation"] = bool(
        active and candidate is not None and mtime is not None and not clock_skew
    )
    entry["intervals_seconds"] = [round(value, 3) for value in intervals[-HEALTH_SAMPLE_WINDOW:]]
    entry["consecutive_suspect"] = consecutive_suspect
    entry["last_age_seconds"] = round(age_seconds, 3) if age_seconds is not None else None
    entry["static_threshold_seconds"] = round(static_threshold_seconds, 3)
    entry["effective_threshold_seconds"] = round(effective_threshold_seconds, 3)
    entry["learned_interval_seconds"] = round(expected_interval, 3) if expected_interval is not None else None
    entry["mode"] = mode
    entry["suspicion"] = round(suspicion, 6) if suspicion is not None else None
    entry["clock_skew"] = clock_skew
    entry["last_health_advanced"] = advanced
    bots_state[bot.name] = entry

    after = json.dumps(entry, sort_keys=True, default=str)
    return HealthAssessment(
        age_minutes=(age_seconds / 60.0) if age_seconds is not None else None,
        static_threshold_minutes=static_threshold_seconds / 60.0,
        effective_threshold_minutes=effective_threshold_seconds / 60.0,
        mode=mode,
        suspicion=suspicion,
        sample_count=len(intervals),
        advanced=advanced,
        clock_skew=clock_skew,
        suspect=suspect,
        stale_confirmed=stale_confirmed,
        consecutive_suspect=consecutive_suspect,
        learned_interval_seconds=expected_interval,
        state_changed=before != after,
        notes=notes,
    )


def find_recent_logs(bot_path: Path, cfg: Dict[str, Any]) -> List[Path]:
    candidates = find_log_candidates(bot_path, cfg)
    reliable = [candidate for candidate in candidates if candidate.reliable]
    reliable.sort(key=lambda item: (-(item.mtime or 0), -item.score))
    return [Path(candidate.path) for candidate in reliable]


def runtime_start_age_minutes(bot_name: str, now: float) -> Optional[float]:
    state = read_runtime_state()
    entry = state.get("bots", {}).get(bot_name, {}) if isinstance(state.get("bots"), dict) else {}
    try:
        started = float(entry.get("started_at_epoch"))
        return max(0.0, (now - started) / 60.0)
    except Exception:
        return None


def expected_runtime_present(bot: BotRecord, processes: Sequence[ProcessInfo], root_pids: Sequence[int]) -> bool:
    roots = set(root_pids)
    kind = bot.launcher_kind
    if kind == "python":
        return any((process.name or "").lower().startswith(("python", "py.exe")) for process in processes)
    if kind == "node":
        return any((process.name or "").lower() == "node.exe" for process in processes)
    if kind == "npm":
        # npm scripts can legitimately launch something other than node.exe.
        return any(process.pid not in roots for process in processes)
    if kind == "powershell":
        return any(
            (process.name or "").lower() in {"powershell.exe", "pwsh.exe"} and process.pid not in roots
            for process in processes
        )
    if kind == "executable":
        expected_name = ntpath.basename(str(bot.launcher).replace("/", "\\")).lower()
        expected_path = normalize_text_path(bot.launcher)
        return any(
            (process.name or "").lower() == expected_name
            or normalize_text_path(process.executable_path) == expected_path
            for process in processes
        )
    return True


def status_for_bots(
    cfg: Dict[str, Any],
    bots: Dict[str, BotRecord],
    *,
    cleanup_stale: bool = True,
    persist_health: bool = True,
) -> List[BotStatus]:
    processes = get_processes(cfg)
    inventory_reliable = process_inventory_reliable(processes)
    now = time.time()
    statuses: List[BotStatus] = []

    loaded_health_state = read_health_state()
    health_schema_blocked = bool(loaded_health_state.get("__newer_schema_blocked"))
    if health_schema_blocked:
        # Never interpret a future schema as if it were current. Monitoring
        # remains available with the fixed threshold and the file is untouched.
        health_state: Dict[str, Any] = {"version": HEALTH_STATE_VERSION, "updated_at": "", "bots": {}}
    else:
        health_state = copy.deepcopy(loaded_health_state)
    health_state_changed = False

    for bot in bots.values():
        warnings: List[str] = []
        bot_path = Path(bot.path)
        launcher_exists = bool(bot.launcher and Path(bot.launcher).exists())
        stop_exists = bool(bot.stop_launcher and Path(bot.stop_launcher).exists())
        if not bot_path.exists():
            warnings.append("folder missing")
        if not bot.launcher:
            warnings.append("no safe start launcher")
        elif not launcher_exists:
            warnings.append("start launcher missing")
        elif not bot.launcher_safe:
            warnings.append("start launcher blocked/unapproved")
        if bot.heartbeat_manual and bot.heartbeat_file and not Path(bot.heartbeat_file).exists():
            warnings.append("manual heartbeat missing")
        elif bot.heartbeat_manual and bot.heartbeat_file and not is_path_within(Path(bot.heartbeat_file), bot_path):
            warnings.append("manual heartbeat outside bot folder")

        tracking = track_bot(bot, processes, cleanup_stale=cleanup_stale and inventory_reliable)
        if tracking.managed_processes:
            active_processes = tracking.managed_processes
            active_roots = tracking.managed_roots
            control_state = "MANAGED"
        elif tracking.observed_processes:
            active_processes = tracking.observed_processes
            active_roots = tracking.observed_roots
            control_state = f"OBSERVED-{tracking.observed_confidence}"
            warnings.append("external process; adopt before force-stop")
        else:
            active_processes = []
            active_roots = []
            control_state = "NONE"

        health_candidates = find_log_candidates(bot_path, cfg)
        contract_candidates = [candidate for candidate in health_candidates if candidate.evidence_kind == "contract"]
        contract_candidate = contract_candidates[0] if contract_candidates else None
        contract_errors = list(contract_candidate.contract_errors) if contract_candidate else []
        if contract_candidate and contract_candidate.contract_errors:
            warnings.append("health contract invalid: " + "; ".join(contract_candidate.contract_errors[:3]))
        contract_pid_match = contract_identity_match(contract_candidate, active_processes) if active_processes else None
        if contract_candidate and active_processes and contract_pid_match is False:
            contract_errors.append("contract PID/start identity does not match the active process tree")
            warnings.append("health contract PID/start identity mismatch; falling back to other evidence")
        health = select_health_candidate(bot, cfg, now=now, candidates=health_candidates)
        if health is not None and health.evidence_kind == "contract" and active_processes and contract_pid_match is False:
            health = select_health_candidate(
                bot,
                cfg,
                now=now,
                candidates=[candidate for candidate in health_candidates if candidate.evidence_kind != "contract"],
            )
        evidence_count = sum(1 for candidate in health_candidates if candidate.reliable)
        if health and health.tier == "manual":
            evidence_count = max(1, evidence_count)
        last_log = health.path if health else ""
        last_mtime = health.mtime if health else None

        startup_age = runtime_start_age_minutes(bot.name, now) if tracking.managed_processes else None
        startup_grace = float(cfg.get("startup_grace_minutes", 3))
        in_startup_grace = bool(startup_age is not None and startup_age <= startup_grace)
        assessment = assess_health_evidence(
            bot,
            health,
            cfg,
            health_state,
            now=now,
            active=bool(active_processes),
            suppress_stale=in_startup_grace,
        )
        health_state_changed = health_state_changed or assessment.state_changed
        age_min = assessment.age_minutes
        threshold = assessment.effective_threshold_minutes
        wrapper_only = bool(
            tracking.managed_processes
            and bot.launcher_kind in {"python", "node", "npm", "executable", "powershell"}
            and not expected_runtime_present(bot, active_processes, [process.pid for process in active_roots])
        )

        if active_processes:
            if (
                in_startup_grace
                and not assessment.clock_skew
                and (health is None or age_min is None or age_min > threshold)
            ):
                status = "STARTING"
            elif wrapper_only:
                status = "START_FAILED/WRAPPER_ONLY"
                warnings.append("launcher shell remains but expected runtime child is missing")
            elif health is None or last_mtime is None:
                status = "RUNNING/NO_HEARTBEAT"
                warnings.append("no reliable operational progress evidence selected")
            elif assessment.clock_skew:
                status = "RUNNING/TIME_SKEW"
                warnings.append("selected health evidence timestamp is ahead of the local clock")
            elif assessment.stale_confirmed:
                status = "RUNNING/STALE"
            elif assessment.suspect:
                status = "RUNNING/SUSPECT"
                warnings.append(
                    "health threshold crossed once; waiting for confirmation before declaring stale"
                )
            elif health.evidence_kind == "contract":
                if health.contract_state == "failed" or health.contract_live is False:
                    status = "RUNNING/UNHEALTHY"
                    warnings.append("structured health contract reports failed or not live")
                elif health.contract_state == "stopping":
                    status = "RUNNING/STOPPING"
                elif health.contract_state == "degraded":
                    status = "RUNNING/DEGRADED"
                    warnings.append("structured health contract reports degraded operation")
                elif health.contract_state == "starting":
                    status = "STARTING"
                elif health.contract_ready is False:
                    status = "STARTING" if in_startup_grace else "RUNNING/NOT_READY"
                    if not in_startup_grace:
                        warnings.append("structured health contract is live but not ready")
                else:
                    status = "RUNNING/HEALTHY"
            else:
                status = "RUNNING/HEALTHY"
        else:
            if (
                health is not None
                and last_mtime is not None
                and not assessment.clock_skew
                and age_min is not None
                and age_min <= threshold
            ):
                if health.evidence_kind == "contract" and health.contract_state == "stopped":
                    status = "STOPPED"
                elif health.evidence_kind == "contract" and health.contract_state == "failed":
                    status = "FAILED/CONTRACT"
                else:
                    status = "RECENT_ACTIVITY/NO_PROCESS"
            else:
                status = "STOPPED"
            if assessment.clock_skew:
                warnings.append("health evidence timestamp is ahead of the local clock; recent activity was not inferred")

        if is_windows_host() and not inventory_reliable:
            status = "UNKNOWN/PROCESS_SCAN"
            control_state = "UNVERIFIED"
            warnings.append("Windows process inventory unavailable; ownership was preserved and control actions are blocked")
        if not bot.enabled:
            status = "RUNNING/CONTROL_OFF" if active_processes else "CONTROL_OFF"
            warnings.append("control disabled")
        if len(active_processes) > 64:
            warnings.append(f"large process set ({len(active_processes)})")

        # Keep the final state transition in the bounded learning record. This
        # is useful in diagnostics but never triggers a restart or stop action.
        health_entry = health_state.get("bots", {}).get(bot.name, {})
        if isinstance(health_entry, dict) and health_entry:
            previous_status = str(health_entry.get("last_status", ""))
            if previous_status != status:
                health_entry["last_status"] = status
                health_entry["last_status_at"] = now
                health_state_changed = True

        process_names = sorted({process.name for process in active_processes if process.name})
        statuses.append(
            BotStatus(
                bot=bot,
                status=status,
                control_state=control_state,
                root_pids=[process.pid for process in active_roots],
                process_count=len(active_processes),
                process_names=process_names,
                last_log=last_log,
                last_log_mtime=last_mtime,
                last_log_age_minutes=age_min,
                health_reliable=bool(health and health.reliable),
                health_score=health.score if health else 0,
                health_tier=health.tier if health else "none",
                health_mode=assessment.mode,
                health_effective_threshold_minutes=assessment.effective_threshold_minutes,
                health_suspicion=assessment.suspicion,
                health_sample_count=assessment.sample_count,
                health_evidence_count=evidence_count,
                health_advanced=assessment.advanced,
                health_clock_skew=assessment.clock_skew,
                health_evidence_kind=health.evidence_kind if health else "none",
                health_contract_state=contract_candidate.contract_state if contract_candidate else "",
                health_contract_live=contract_candidate.contract_live if contract_candidate else None,
                health_contract_ready=contract_candidate.contract_ready if contract_candidate else None,
                health_contract_pid=contract_candidate.contract_pid if contract_candidate else None,
                health_contract_pid_match=contract_pid_match,
                health_contract_heartbeat_sequence=contract_candidate.contract_heartbeat_sequence if contract_candidate else None,
                health_contract_progress_sequence=contract_candidate.contract_progress_sequence if contract_candidate else None,
                health_contract_message=contract_candidate.contract_message if contract_candidate else "",
                health_contract_errors=contract_errors,
                launcher_exists=launcher_exists,
                stop_launcher_exists=stop_exists,
                warnings=warnings,
            )
        )

    if persist_health and health_state_changed and not health_schema_blocked:
        try:
            write_health_state(health_state)
        except Exception as exc:
            log_event(f"Could not persist adaptive health state: {exc}", "WARNING")
    return statuses


def fmt_age(minutes: Optional[float]) -> str:
    if minutes is None:
        return "--"
    if minutes < 1:
        return "<1m"
    if minutes < 60:
        return f"{int(minutes)}m"
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.1f}h"
    return f"{hours / 24:.1f}d"


def fmt_time(timestamp: Optional[float]) -> str:
    if timestamp is None:
        return "--"
    return dt.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")


def truncate(value: str, width: int) -> str:
    value = str(value)
    if width <= 3:
        return value[:width]
    if len(value) <= width:
        return value
    return value[: width - 3] + "..."


def install_location_warning() -> Optional[str]:
    text = normalize_text_path(str(app_root()))
    if any(f"\\{part}\\" in text for part in ("downloads", "temp", "tmp")):
        return "Manager is running from a temporary/download location; a stable folder such as C:\\Bots\\_BotOpsManager is recommended."
    return None


def path_is_absolute_like(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    return Path(text).expanduser().is_absolute() or ntpath.isabs(text)


def path_text_within(root_text: str, child_text: str) -> bool:
    if not root_text or not child_text:
        return False
    root_norm = normalize_text_path(root_text).rstrip("\\/")
    child_norm = normalize_text_path(child_text).rstrip("\\/")
    if child_norm == root_norm:
        return True
    return child_norm.startswith(root_norm + "\\") or child_norm.startswith(root_norm + "/")


def build_path_targeting_report(cfg: Dict[str, Any], bots: Optional[Dict[str, BotRecord]] = None) -> Dict[str, Any]:
    root_text = str(cfg.get("bots_root", DEFAULT_BOTS_ROOT)).strip() or DEFAULT_BOTS_ROOT
    root = Path(root_text).expanduser()
    registry = read_registry()
    registry_bots = _registry_semantic_bots(registry)
    active_bots = bots if bots is not None else {name: bot_record_from_dict(name, data) for name, data in registry_bots.items() if isinstance(data, dict)}
    missing_registry_paths: List[str] = []
    outside_root_paths: List[str] = []
    for name, data in registry_bots.items():
        if not isinstance(data, dict):
            continue
        path_text = str(data.get("path", ""))
        if not path_text:
            continue
        path = Path(path_text)
        if not path.exists():
            missing_registry_paths.append(name)
        if root.exists() and not path_text_within(root_text, path_text):
            outside_root_paths.append(name)
    findings: List[str] = []
    if not path_is_absolute_like(root_text):
        findings.append("bots_root is not absolute-like; using a full local path is safer")
    if not root.exists():
        findings.append("bots_root does not exist; scan will not rewrite registry")
    try:
        if root.exists() and root.resolve() == app_root().resolve():
            findings.append("bots_root points at the manager folder; set it to the parent bot collection instead")
    except Exception:
        pass
    if outside_root_paths:
        findings.append(f"registry has {len(outside_root_paths)} path(s) outside the effective bots_root")
    return {
        "bots_root": str(root),
        "bots_root_source": str(cfg.get("_bots_root_source", "unknown")),
        "exists": root.exists(),
        "absolute_like": path_is_absolute_like(root_text),
        "active_registry_entries": len(active_bots),
        "missing_registry_path_count": len(missing_registry_paths),
        "missing_registry_path_names": missing_registry_paths[:20],
        "outside_root_path_count": len(outside_root_paths),
        "outside_root_path_names": outside_root_paths[:20],
        "scan_write_guard": "enabled_no_rewrite_when_root_missing",
        "repair_hint": "Set BOTOPS_BOTS_ROOT for a temporary target, use --root for a one-off CLI target, or edit state\\bot_manager_config.json for a persistent target.",
        "findings": findings,
    }


def dashboard_text(cfg: Dict[str, Any], statuses: Sequence[BotStatus]) -> str:
    root = str(cfg.get("bots_root", DEFAULT_BOTS_ROOT))
    lines: List[str] = [
        f"{APP_NAME} v{APP_VERSION} | root: {root} | force-stop scope: managed/adopted roots only",
        f"Generated: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    location_warning = install_location_warning()
    if location_warning:
        lines.append("NOTICE: " + location_warning)
    for warning in state_schema_warnings():
        lines.append("WARNING: " + warning)
    if not Path(root).exists():
        lines.append(f"WARNING: bots root does not exist: {root}")
    running = sum(1 for status in statuses if status.status.startswith("RUNNING") or status.status == "STARTING")
    healthy = sum(1 for status in statuses if status.status == "RUNNING/HEALTHY")
    suspect = sum(1 for status in statuses if status.status == "RUNNING/SUSPECT")
    stale = sum(1 for status in statuses if status.status == "RUNNING/STALE")
    clock_skew = sum(1 for status in statuses if status.status == "RUNNING/TIME_SKEW")
    observed = sum(1 for status in statuses if status.control_state.startswith("OBSERVED"))
    failed = sum(1 for status in statuses if status.status.startswith("START_FAILED"))
    structured = sum(1 for status in statuses if status.health_contract_state or status.health_contract_errors)
    contract_attention = sum(
        1
        for status in statuses
        if status.status in {"RUNNING/UNHEALTHY", "RUNNING/DEGRADED", "RUNNING/NOT_READY", "FAILED/CONTRACT"}
    )
    lines.append(
        f"Summary: {len(statuses)} discovered | {running} running | {healthy} healthy | "
        f"{suspect} suspect | {stale} stale | {clock_skew} time-skew | "
        f"{failed} start-failed | {observed} observed-only | {structured} contracts/{contract_attention} attention"
    )
    lines.append("")
    if not statuses:
        lines.append("No bot folders detected. Add folders below the root and run Rescan.")
        return "\n".join(lines)
    header = (
        f"{'#':>2}  {'Bot':<25} {'Type':<8} {'State':<25} {'Tracking':<15} "
        f"{'Roots/Proc':<11} {'Health':<8} {'Start launcher':<30}"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for index, status in enumerate(statuses, start=1):
        bot = status.bot
        roots_proc = f"{len(status.root_pids)}/{status.process_count}" if status.process_count else "--"
        launcher = Path(bot.launcher).name if bot.launcher else "--"
        if bot.launcher and not bot.launcher_safe:
            launcher = "BLOCKED:" + launcher
        warning = f" !{len(status.warnings)}" if status.warnings else ""
        lines.append(
            f"{index:>2}  {truncate(bot.name, 25):<25} {truncate(bot.category, 8):<8} "
            f"{truncate(status.status + warning, 25):<25} {truncate(status.control_state, 15):<15} "
            f"{truncate(roots_proc, 11):<11} {fmt_age(status.last_log_age_minutes):<8} {truncate(launcher, 30):<30}"
        )
    lines.append("")
    lines.append("Tracking: MANAGED = started/adopted and identity-verified; OBSERVED = monitor-only until adopted.")
    lines.append("Health separates process presence from useful progress; optional botops_health_v1 contracts add startup/readiness/liveness/degraded state without a service or dependency.")
    lines.append("SUSPECT is debounced, contract identity can be PID-bound, and BotOps never auto-restarts or stops a bot from health evidence.")
    return "\n".join(lines)


def launcher_audit_text(cfg: Dict[str, Any], bots: Dict[str, BotRecord]) -> str:
    lines = [
        f"{APP_NAME} v{APP_VERSION} launcher safety audit",
        f"Root: {cfg.get('bots_root', DEFAULT_BOTS_ROOT)}",
        f"Generated: {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    if not bots:
        lines.append("No bot folders detected.")
        return "\n".join(lines)
    for bot in bots.values():
        start_name = Path(bot.launcher).name if bot.launcher else "NO SAFE START LAUNCHER"
        start_state = "SAFE" if bot.launcher and bot.launcher_safe else "REVIEW"
        stop_name = Path(bot.stop_launcher).name if bot.stop_launcher else "--"
        lines.append(f"[{start_state:<6}] {bot.name}")
        lines.append(f"         start: {start_name} (score {bot.launcher_score})")
        lines.append(f"         stop : {stop_name}")
        if bot.launcher_reason:
            lines.append(f"         why  : {bot.launcher_reason}")
    lines.extend(
        [
            "",
            "Start-role detection blocks names associated with stop/emergency/build/deploy/export/setup/test work.",
            "Use Full Manager > bot number > Profile to correct a launcher or heartbeat selection.",
        ]
    )
    return "\n".join(lines)


def status_to_dict(status: BotStatus) -> Dict[str, Any]:
    return {
        "name": status.bot.name,
        "category": status.bot.category,
        "path": status.bot.path,
        "status": status.status,
        "control_state": status.control_state,
        "root_pids": status.root_pids,
        "process_count": status.process_count,
        "process_names": status.process_names,
        "launcher": status.bot.launcher,
        "launcher_safe": status.bot.launcher_safe,
        "launcher_score": status.bot.launcher_score,
        "stop_launcher": status.bot.stop_launcher,
        "heartbeat_file": status.last_log,
        "heartbeat_time": fmt_time(status.last_log_mtime),
        "heartbeat_age_minutes": status.last_log_age_minutes,
        "health_reliable": status.health_reliable,
        "health_score": status.health_score,
        "health_tier": status.health_tier,
        "health_mode": status.health_mode,
        "health_effective_threshold_minutes": status.health_effective_threshold_minutes,
        "health_suspicion": status.health_suspicion,
        "health_sample_count": status.health_sample_count,
        "health_evidence_count": status.health_evidence_count,
        "health_advanced": status.health_advanced,
        "health_clock_skew": status.health_clock_skew,
        "health_evidence_kind": status.health_evidence_kind,
        "health_contract": {
            "schema": HEALTH_CONTRACT_SCHEMA if status.health_contract_state or status.health_contract_errors else "",
            "state": status.health_contract_state,
            "live": status.health_contract_live,
            "ready": status.health_contract_ready,
            "pid": status.health_contract_pid,
            "pid_match": status.health_contract_pid_match,
            "heartbeat_sequence": status.health_contract_heartbeat_sequence,
            "progress_sequence": status.health_contract_progress_sequence,
            "message": status.health_contract_message,
            "errors": status.health_contract_errors,
        },
        "warnings": status.warnings,
    }


def prometheus_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def write_observability_outputs(cfg: Dict[str, Any], statuses: Sequence[BotStatus]) -> None:
    payload = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "generated_at": utc_stamp(),
        "bots_root": str(cfg.get("bots_root", DEFAULT_BOTS_ROOT)),
        "statuses": [status_to_dict(status) for status in statuses],
    }
    try:
        write_json(latest_status_path(), payload, backup=False)
    except Exception as exc:
        log_event(f"Could not write latest status snapshot: {exc}", "WARNING")
    metric_lines = [
        "# BotOps Manager local metrics (OpenMetrics/Prometheus text format)",
        "# TYPE botops_snapshot_timestamp_seconds gauge",
        f"botops_snapshot_timestamp_seconds {time.time():.3f}",
        f"# BotOps run_id {prometheus_escape(RUN_ID)}",
        f"botops_info{{version=\"{prometheus_escape(APP_VERSION)}\"}} 1",
        f"botops_control_action_lock_active {1 if read_control_action_lock().get('active') else 0}",
    ]
    for status in statuses:
        label = f'bot="{prometheus_escape(status.bot.name)}",category="{prometheus_escape(status.bot.category)}"'
        status_label = f'{label},status="{prometheus_escape(status.status)}"'
        running = int(status.status.startswith("RUNNING") or status.status == "STARTING")
        managed = int(status.control_state == "MANAGED")
        metric_lines.append(f"botops_bot_running{{{label}}} {running}")
        metric_lines.append(f"botops_bot_managed{{{label}}} {managed}")
        metric_lines.append(f"botops_bot_observed{{{label}}} {int(status.control_state.startswith('OBSERVED'))}")
        metric_lines.append(f"botops_bot_status{{{status_label}}} 1")
        metric_lines.append(f"botops_bot_healthy{{{label}}} {int(status.status == 'RUNNING/HEALTHY')}")
        metric_lines.append(f"botops_bot_suspect{{{label}}} {int(status.status == 'RUNNING/SUSPECT')}")
        metric_lines.append(f"botops_bot_stale{{{label}}} {int(status.status == 'RUNNING/STALE')}")
        metric_lines.append(f"botops_bot_time_skew{{{label}}} {int(status.status == 'RUNNING/TIME_SKEW')}")
        metric_lines.append(f"botops_bot_start_failed{{{label}}} {int(status.status.startswith('START_FAILED'))}")
        metric_lines.append(f"botops_bot_process_count{{{label}}} {status.process_count}")
        metric_lines.append(f"botops_bot_launcher_safe{{{label}}} {int(status.bot.launcher_safe)}")
        metric_lines.append(f"botops_bot_control_enabled{{{label}}} {int(status.bot.enabled)}")
        metric_lines.append(f"botops_bot_health_reliable{{{label}}} {int(status.health_reliable)}")
        metric_lines.append(f"botops_bot_health_advanced{{{label}}} {int(status.health_advanced)}")
        metric_lines.append(f"botops_bot_health_clock_skew{{{label}}} {int(status.health_clock_skew)}")
        metric_lines.append(f"botops_bot_health_contract_present{{{label}}} {int(bool(status.health_contract_state or status.health_contract_errors))}")
        metric_lines.append(f"botops_bot_health_contract_live{{{label}}} {int(status.health_contract_live is True)}")
        metric_lines.append(f"botops_bot_health_contract_ready{{{label}}} {int(status.health_contract_ready is True)}")
        metric_lines.append(f"botops_bot_health_contract_error_count{{{label}}} {len(status.health_contract_errors)}")
        if status.health_contract_state:
            contract_label = f'{label},state="{prometheus_escape(status.health_contract_state)}"'
            metric_lines.append(f"botops_bot_health_contract_state{{{contract_label}}} 1")
        metric_lines.append(f"botops_bot_health_sample_count{{{label}}} {status.health_sample_count}")
        metric_lines.append(f"botops_bot_health_evidence_count{{{label}}} {status.health_evidence_count}")
        mode_label = f'{label},mode="{prometheus_escape(status.health_mode)}",tier="{prometheus_escape(status.health_tier)}"'
        metric_lines.append(f"botops_bot_health_model_info{{{mode_label}}} 1")
        if status.last_log_age_minutes is not None:
            metric_lines.append(f"botops_bot_health_age_seconds{{{label}}} {status.last_log_age_minutes * 60:.3f}")
        if status.health_suspicion is not None:
            metric_lines.append(f"botops_bot_health_suspicion{{{label}}} {status.health_suspicion:.6f}")
        static_threshold = float(
            status.bot.stale_minutes
            if status.bot.stale_minutes is not None
            else cfg.get("stale_minutes", 10)
        )
        effective_threshold = float(
            status.health_effective_threshold_minutes
            if status.health_effective_threshold_minutes is not None
            else static_threshold
        )
        # Preserve the legacy metric as the configured/static threshold and add
        # an explicit effective metric for adaptive consumers.
        metric_lines.append(f"botops_bot_stale_threshold_seconds{{{label}}} {static_threshold * 60:.3f}")
        metric_lines.append(f"botops_bot_effective_stale_threshold_seconds{{{label}}} {effective_threshold * 60:.3f}")
    try:
        atomic_write_text(metrics_path(), "\n".join(metric_lines) + "\n", backup=False)
    except Exception as exc:
        log_event(f"Could not write metrics snapshot: {exc}", "WARNING")


def print_dashboard(cfg: Dict[str, Any], rescan: bool = False) -> List[BotStatus]:
    bots = get_bots(cfg, rescan=rescan)
    statuses = status_for_bots(cfg, bots)
    print(dashboard_text(cfg, statuses))
    write_observability_outputs(cfg, statuses)
    return statuses


def choose_bot_by_token(bots: Dict[str, BotRecord], token: str) -> Optional[BotRecord]:
    if not token:
        return None
    token_lower = token.lower().strip()
    lookup = {name.lower(): name for name in bots}
    if token_lower in lookup:
        return bots[lookup[token_lower]]
    if token_lower.isdigit():
        index = int(token_lower) - 1
        values = list(bots.values())
        if 0 <= index < len(values):
            return values[index]
    matches = [bot for bot in bots.values() if token_lower in bot.name.lower()]
    return matches[0] if len(matches) == 1 else None


def confirm_action(prompt: str, cfg: Dict[str, Any], assume_yes: bool = False) -> bool:
    if assume_yes or not cfg.get("confirm_start_stop", True):
        return True
    print(prompt)
    return input("Continue? [y/N]: ").strip().lower() in {"y", "yes"}


def confirm_force_action(bot: BotRecord, prompt: str, cfg: Dict[str, Any], assume_yes: bool = False) -> bool:
    if assume_yes:
        return True
    print(prompt)
    typed = input(f"Type the bot name exactly to confirm ({bot.name}): ").strip()
    return typed == bot.name


def cmd_quote(value: str) -> str:
    value = str(value)
    if '"' in value:
        raise ValueError("Windows command paths cannot contain a double quote.")
    if "\r" in value or "\n" in value:
        raise ValueError("Windows command paths cannot contain a newline.")
    # cmd.exe expands %NAME% even inside double quotes. Refuse that rare path
    # form instead of guessing at interactive-vs-batch percent escaping.
    if "%" in value:
        raise ValueError("Windows command paths containing % are not supported safely.")
    return f'"{value}"'


def find_python_for_bot(bot_path: Path) -> str:
    candidates = [
        bot_path / ".venv" / "Scripts" / "python.exe",
        bot_path / "venv" / "Scripts" / "python.exe",
        bot_path / "env" / "Scripts" / "python.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return cmd_quote(str(candidate))
    # Prefer the Windows Python launcher for generic .py bots so BotOps does
    # not accidentally reuse a manager/foreign virtualenv interpreter.
    if is_windows_host():
        if shutil.which("py.exe"):
            return "py -3"
        if shutil.which("python.exe"):
            return "python"
    executable = Path(sys.executable)
    if executable.exists() and executable.name.lower().startswith("python"):
        return cmd_quote(str(executable))
    return "py -3"


def build_runner_command_path(path: Path, kind: str, bot_path: Path, cfg: Dict[str, Any]) -> str:
    quoted = cmd_quote(str(path))
    if kind == "python":
        return f"{find_python_for_bot(bot_path)} {quoted}"
    if kind == "node":
        return f"node {quoted}"
    if kind == "npm":
        return f"npm --prefix {cmd_quote(str(path.parent))} start"
    if kind == "powershell":
        # Do not bypass the machine/user execution policy. A blocked script must
        # be repaired, signed, or launched through a user-approved policy path;
        # BotOps never weakens that boundary automatically.
        # The outer cmd.exe window controls whether the console remains open.
        return f"powershell.exe -NoProfile -File {quoted}"
    if kind == "batch":
        return f"call {quoted}"
    return quoted


def build_runner_command(bot: BotRecord, cfg: Optional[Dict[str, Any]] = None) -> str:
    if not bot.launcher:
        raise ValueError("No start launcher is configured.")
    return build_runner_command_path(Path(bot.launcher), bot.launcher_kind, Path(bot.path), cfg or DEFAULT_CONFIG)


def popen_new_console(command: str, cwd: Path, keep_open: bool, env: Optional[Dict[str, str]] = None) -> subprocess.Popen[Any]:
    if not is_windows_host():
        raise OSError("New-console launching is Windows-only.")
    switch = "/k" if keep_open else "/c"
    creationflags = int(getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
    return subprocess.Popen(
        ["cmd.exe", "/d", "/v:off", switch, command],
        cwd=str(cwd),
        creationflags=creationflags,
        close_fds=True,
        env=env,
    )


def child_environment(bot: BotRecord, action: str) -> Dict[str, str]:
    env = dict(os.environ)
    env.setdefault("BOTOPS_RUN_ID", RUN_ID)
    env["BOTOPS_PARENT_RUN_ID"] = RUN_ID
    env["BOTOPS_BOT_NAME"] = bot.name
    env["BOTOPS_ACTION"] = action
    return env


def start_bot(
    bot: BotRecord,
    cfg: Dict[str, Any],
    assume_yes: bool = False,
    allow_duplicate: bool = False,
) -> bool:
    schema_block = control_schema_block_reason()
    if schema_block:
        print(schema_block)
        return False
    if not bot.enabled:
        print(f"Control is disabled for {bot.name}. Enable it from the bot menu first.")
        return False
    if not bot.launcher:
        print(f"No safe start launcher is configured for {bot.name}. Use Profile to select one.")
        return False
    if not bot.launcher_safe:
        print(f"Start launcher is blocked or unapproved: {bot.launcher}")
        return False
    launcher = Path(bot.launcher)
    if not launcher.exists():
        print(f"Start launcher is missing: {launcher}")
        return False
    if not is_windows_host():
        print("Starting bots from BotOps is supported on Windows only.")
        return False

    processes = get_processes(cfg, force=True)
    if not process_inventory_reliable(processes):
        print("Start blocked: Windows process inventory is unavailable, so BotOps cannot rule out an already-running instance.")
        return False
    tracking = track_bot(bot, processes)
    already_running = tracking.managed_processes or tracking.observed_processes
    if already_running and not allow_duplicate:
        mode = "managed" if tracking.managed_processes else "observed external"
        print(f"Start blocked: {bot.name} already has a {mode} process set. This prevents accidental duplicate trading instances.")
        if tracking.observed_processes:
            print("Use Adopt in the bot menu after reviewing the observed roots.")
        return False

    if not confirm_action(
        f"Start {bot.name} with {launcher.name}? Its own code may connect to exchanges and act under its current configuration.",
        cfg,
        assume_yes,
    ):
        print("Start canceled.")
        return False
    try:
        with control_action_lock(bot.name, "start", cfg):
            schema_block = control_schema_block_reason()
            if schema_block:
                print(schema_block)
                return False
            processes = get_processes(cfg, force=True)
            if not process_inventory_reliable(processes):
                print("Start blocked: Windows process inventory is unavailable, so BotOps cannot rule out an already-running instance.")
                return False
            tracking = track_bot(bot, processes)
            already_running = tracking.managed_processes or tracking.observed_processes
            if already_running and not allow_duplicate:
                mode = "managed" if tracking.managed_processes else "observed external"
                print(f"Start blocked: {bot.name} already has a {mode} process set. This prevents accidental duplicate trading instances.")
                if tracking.observed_processes:
                    print("Use Adopt in the bot menu after reviewing the observed roots.")
                return False
            bot_path = Path(bot.path)
            runner = build_runner_command(bot, cfg)
            title = sanitize_title(f"BotOps - {bot.name}")
            command = f"title {title} & cd /d {cmd_quote(str(bot_path))} & {runner}"
            started_at = time.time()
            process = popen_new_console(command, bot_path, keep_open=True, env=child_environment(bot, "start"))
            settle = max(0.0, float(cfg.get("start_settle_seconds", 1.5)))
            if settle:
                time.sleep(settle)
            refreshed = get_processes(cfg, force=True)
            by_pid = {item.pid: item for item in refreshed}
            root = by_pid.get(process.pid)
            roots: List[ProcessInfo] = [root] if root else []
            if not roots:
                observed, observed_roots, _confidence, _reasons = observed_tracking(bot, refreshed)
                roots = [item for item in observed_roots if item.creation_time is None or item.creation_time >= started_at - 5]
                if not roots and observed:
                    roots = root_processes(observed)
            if not roots:
                roots = [ProcessInfo(pid=process.pid, name="cmd.exe", creation_time=started_at)]
            record_runtime_roots(bot, roots, started_at)
            log_event(f"Start requested for {bot.name}; launcher={launcher}; root_pids={','.join(str(item.pid) for item in roots)}")
            print(f"Start requested: {bot.name} (tracked root PID{'s' if len(roots) != 1 else ''}: {', '.join(str(item.pid) for item in roots)}; identity will be re-verified on refresh)")
            return True
    except Exception as exc:
        log_event(f"Start failed for {bot.name}: {exc}", "ERROR")
        print(f"Start failed: {exc}")
        return False


def run_stop_script(bot: BotRecord, cfg: Dict[str, Any], assume_yes: bool = False) -> bool:
    schema_block = control_schema_block_reason()
    if schema_block:
        print(schema_block)
        return False
    if not bot.enabled:
        print(f"Control is disabled for {bot.name}.")
        return False
    if not bot.stop_launcher:
        print(f"No stop script is configured for {bot.name}. Use Profile to select one, or force-stop a managed tree.")
        return False
    stop_path = Path(bot.stop_launcher)
    if not stop_path.exists():
        print(f"Stop script is missing: {stop_path}")
        return False
    if not is_path_within(stop_path, Path(bot.path)):
        print("Stop script is outside the bot folder and was blocked. Re-select it from Profile.")
        return False
    if not stop_scope_matches_start(Path(bot.path), bot.launcher, str(stop_path)):
        print("Stop script is in a different nested control scope than the start launcher. Re-select it from Profile.")
        return False
    stop_candidate = score_stop_candidate(stop_path, Path(bot.path), cfg)
    if stop_candidate.blocked or stop_candidate.score <= -999:
        print("Stop script no longer passes the stop-role safety audit. Re-select it from Profile.")
        return False
    if not is_windows_host():
        print("Stop-script launching is supported on Windows only.")
        return False
    if not confirm_action(
        f"Run stop script {stop_path.name} for {bot.name}? Review the file name carefully; emergency-stop scripts can cancel orders or shut down trading.",
        cfg,
        assume_yes,
    ):
        print("Stop canceled.")
        return False
    try:
        with control_action_lock(bot.name, "stop-script", cfg):
            bot_path = Path(bot.path)
            runner = build_runner_command_path(stop_path, bot.stop_launcher_kind, bot_path, cfg)
            title = sanitize_title(f"BotOps Stop - {bot.name}")
            command = f"title {title} & cd /d {cmd_quote(str(bot_path))} & {runner}"
            popen_new_console(command, bot_path, keep_open=False, env=child_environment(bot, "stop-script"))
            log_event(f"Stop script launched for {bot.name}: {stop_path}")
            deadline = time.monotonic() + max(0.0, float(cfg.get("stop_wait_seconds", 8)))
            inventory_verified = False
            while time.monotonic() < deadline:
                time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
                refreshed = get_processes(cfg, force=True)
                if not process_inventory_reliable(refreshed):
                    continue
                inventory_verified = True
                tracking = track_bot(bot, refreshed)
                if not tracking.managed_processes and not tracking.observed_processes:
                    clear_runtime_bot(bot.name)
                    print(f"Stop script completed and no matching process remains: {bot.name}")
                    return True
            if not inventory_verified:
                print("Stop script was launched, but Windows process inventory was unavailable; ownership was preserved and completion could not be verified.")
                return True
            print(f"Stop script was launched. A matching process is still visible; review the dashboard before forcing termination.")
            return True
    except Exception as exc:
        log_event(f"Stop script failed for {bot.name}: {exc}", "ERROR")
        print(f"Stop script failed: {exc}")
        return False


def adopt_bot(bot: BotRecord, cfg: Dict[str, Any], assume_yes: bool = False) -> bool:
    schema_block = control_schema_block_reason()
    if schema_block:
        print(schema_block)
        return False
    if not bot.enabled:
        print(f"Control is disabled for {bot.name}.")
        return False
    processes = get_processes(cfg, force=True)
    if not process_inventory_reliable(processes):
        print("Adoption blocked: Windows process inventory is unavailable or missing identity timestamps.")
        return False
    tracking = track_bot(bot, processes)
    if tracking.managed_processes:
        print(f"{bot.name} is already managed.")
        return True
    roots = tracking.observed_roots
    if not roots:
        print(f"No observed process roots are available to adopt for {bot.name}.")
        return False
    unidentified = [process for process in roots if process.creation_time is None]
    if unidentified:
        print("Adoption blocked: one or more roots have no creation timestamp, so PID reuse cannot be ruled out.")
        return False
    maximum = int(cfg.get("max_adopt_roots", 16))
    if len(roots) > maximum:
        print(f"Adoption blocked: {len(roots)} roots exceed the safety limit of {maximum}. Refine the bot launcher/profile first.")
        return False
    details = ", ".join(
        f"{process.pid}:{process.name}@{fmt_time(process.creation_time)}" for process in roots
    )
    reason_text = "; ".join(tracking.observed_reasons[:6])
    if not confirm_force_action(
        bot,
        f"CONTROL OWNERSHIP CHANGE: adopt observed {tracking.observed_confidence.lower()}-confidence root process(es) for {bot.name}: {details}. Evidence: {reason_text or 'path match'}. Future force-stop may terminate these trees.",
        cfg,
        assume_yes,
    ):
        print("Adoption canceled.")
        return False
    try:
        with control_action_lock(bot.name, "adopt", cfg):
            refreshed = get_processes(cfg, force=True)
            if not process_inventory_reliable(refreshed):
                print("Adoption blocked after confirmation: Windows process inventory became unavailable.")
                return False
            refreshed_tracking = track_bot(bot, refreshed)
            refreshed_roots = refreshed_tracking.observed_roots
            original = sorted((process.pid, process.creation_time) for process in roots)
            current = sorted((process.pid, process.creation_time) for process in refreshed_roots)
            if original != current:
                print("Adoption blocked after confirmation: observed process roots changed. Re-open the bot details and review again.")
                return False
            started_at = min((process.creation_time for process in refreshed_roots if process.creation_time is not None), default=time.time())
            record_runtime_roots(bot, refreshed_roots, started_at)
            log_event(f"Adopted observed roots for {bot.name}: {details}")
            print(f"Adopted {len(refreshed_roots)} root process(es) for {bot.name}.")
            return True
    except Exception as exc:
        log_event(f"Adoption failed for {bot.name}: {exc}", "ERROR")
        print(f"Adoption failed: {exc}")
        return False


def force_stop_bot(bot: BotRecord, cfg: Dict[str, Any], assume_yes: bool = False) -> bool:
    schema_block = control_schema_block_reason()
    if schema_block:
        print(schema_block)
        return False
    if not bot.enabled:
        print(f"Control is disabled for {bot.name}.")
        return False
    if not is_windows_host():
        print("Force-stop is supported on Windows only.")
        return False
    processes = get_processes(cfg, force=True)
    if not process_inventory_reliable(processes):
        print("Force-stop blocked: Windows process inventory is unavailable or incomplete; ownership state was preserved.")
        return False
    tracking = track_bot(bot, processes)
    roots = tracking.managed_roots
    if not roots:
        if tracking.observed_processes:
            print("Force-stop blocked: processes are observed but not managed. Adopt them explicitly after review.")
        else:
            print(f"No verified managed process root found for {bot.name}.")
        return False
    maximum = int(cfg.get("max_force_stop_roots", 16))
    if len(roots) > maximum:
        print(f"Force-stop blocked: {len(roots)} roots exceed the configured safety limit of {maximum}.")
        return False
    details = ", ".join(f"{process.pid}:{process.name}" for process in roots)
    if not confirm_force_action(
        bot,
        f"HIGH-RISK ACTION: force-stop verified managed tree(s) for {bot.name}: {details}. This can interrupt live positions/orders and prevents cleanup unless the bot handles termination.",
        cfg,
        assume_yes,
    ):
        print("Force-stop canceled.")
        return False
    try:
        with control_action_lock(bot.name, "force-stop", cfg):
            refreshed_before = get_processes(cfg, force=True)
            if not process_inventory_reliable(refreshed_before):
                print("Force-stop blocked after confirmation: Windows process inventory became unavailable; ownership state was preserved.")
                return False
            refreshed_tracking = track_bot(bot, refreshed_before)
            refreshed_roots = refreshed_tracking.managed_roots
            original = sorted((process.pid, process.creation_time) for process in roots)
            current = sorted((process.pid, process.creation_time) for process in refreshed_roots)
            if original != current:
                print("Force-stop blocked after confirmation: managed roots changed. Re-open the bot details and review again.")
                return False
            ok = True
            for root in refreshed_roots:
                try:
                    completed = subprocess.run(
                        ["taskkill", "/PID", str(root.pid), "/T", "/F"],
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=20,
                    )
                except subprocess.TimeoutExpired:
                    ok = False
                    print(f"taskkill timed out for PID {root.pid}.")
                    continue
                if completed.returncode != 0:
                    ok = False
                    output = (completed.stdout + completed.stderr).strip()
                    if output:
                        print(output)
            time.sleep(0.5)
            refreshed_processes = get_processes(cfg, force=True)
            still_alive: List[int] = []
            uncertain: List[int] = []
            if not process_inventory_reliable(refreshed_processes):
                uncertain = [root.pid for root in refreshed_roots]
            else:
                refreshed = {process.pid: process for process in refreshed_processes}
                for root in refreshed_roots:
                    current_process = refreshed.get(root.pid)
                    if current_process is None:
                        continue
                    if current_process.creation_time is None or root.creation_time is None:
                        uncertain.append(root.pid)
                    elif abs(current_process.creation_time - root.creation_time) <= 4:
                        still_alive.append(root.pid)
                    # A different CreationDate means the original root exited and the
                    # PID was reused; never touch the replacement process.
            if still_alive:
                ok = False
                print("Verified root process(es) still visible: " + ", ".join(str(pid) for pid in still_alive))
            if uncertain:
                ok = False
                print("Could not verify termination for root PID(s): " + ", ".join(str(pid) for pid in uncertain) + ". Ownership was preserved.")
            if not still_alive and not uncertain:
                clear_runtime_bot(bot.name)
            log_event(f"Force-stop for {bot.name}; roots={details}; ok={ok}", "WARNING")
            print(f"Force-stop result for {bot.name}: {'completed' if ok else 'some errors'}")
            return ok
    except Exception as exc:
        log_event(f"Force-stop failed for {bot.name}: {exc}", "ERROR")
        print(f"Force-stop failed: {exc}")
        return False


def stop_bot(bot: BotRecord, cfg: Dict[str, Any], force: bool = False, assume_yes: bool = False) -> bool:
    return force_stop_bot(bot, cfg, assume_yes) if force else run_stop_script(bot, cfg, assume_yes)


def open_path(path: Path) -> None:
    try:
        if is_windows_host():
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception as exc:
        print(f"Could not open {path}: {exc}")


def tail_file(path: Path, lines: int = 80) -> str:
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            end = stream.tell()
            block = 4096
            data = b""
            position = end
            while position > 0 and data.count(b"\n") <= lines:
                position = max(0, position - block)
                stream.seek(position)
                data = stream.read(end - position)
            return "\n".join(data.decode("utf-8", errors="replace").splitlines()[-lines:])
    except Exception as exc:
        return f"Could not read file: {exc}"


def tail_bot(bot: BotRecord, cfg: Dict[str, Any], lines: int = 80) -> None:
    health = select_health_candidate(bot, cfg)
    if health is None:
        candidates = find_log_candidates(Path(bot.path), cfg)
        print(f"No reliable operational log/heartbeat is selected for {bot.name}.")
        if candidates:
            print("Use Profile -> heartbeat to select one. Highest-scoring candidates:")
            for candidate in candidates[:5]:
                print(f"  score {candidate.score:>4}: {candidate.path}")
        return
    print(f"--- Tail: {health.path} (score {health.score}) ---")
    print(tail_file(Path(health.path), max(1, min(lines, 1000))))


def bot_detail_text(cfg: Dict[str, Any], status: BotStatus) -> str:
    bot = status.bot
    lines = [
        f"Bot: {bot.name}",
        f"Category: {bot.category}",
        f"State: {status.status}",
        f"Tracking/control: {status.control_state}",
        f"Path: {bot.path}",
        f"Start launcher: {bot.launcher or '--'} ({bot.launcher_kind}; safe={bot.launcher_safe}; score={bot.launcher_score})",
        f"Start rationale: {bot.launcher_reason or '--'}",
        f"Stop launcher: {bot.stop_launcher or '--'} ({bot.stop_launcher_kind})",
        f"Control enabled: {bot.enabled}",
        f"Root PIDs: {', '.join(str(pid) for pid in status.root_pids) if status.root_pids else '--'}",
        f"Process count/names: {status.process_count} / {', '.join(status.process_names) if status.process_names else '--'}",
        f"Health file: {status.last_log or '--'}",
        f"Health age: {fmt_age(status.last_log_age_minutes)} (reliable={status.health_reliable}; score={status.health_score}; tier={status.health_tier})",
        f"Health model: {status.health_mode}; effective stale threshold={fmt_age(status.health_effective_threshold_minutes)}; learned samples={status.health_sample_count}; evidence files={status.health_evidence_count}",
        f"Health suspicion/progress: {status.health_suspicion if status.health_suspicion is not None else '--'} / {'advanced' if status.health_advanced else 'no new mtime'}; clock_skew={status.health_clock_skew}",
        f"Structured contract: state={status.health_contract_state or '--'} live={status.health_contract_live} ready={status.health_contract_ready} pid={status.health_contract_pid or '--'} pid_match={status.health_contract_pid_match}",
        f"Contract sequences: heartbeat={status.health_contract_heartbeat_sequence if status.health_contract_heartbeat_sequence is not None else '--'} progress={status.health_contract_progress_sequence if status.health_contract_progress_sequence is not None else '--'}; message={status.health_contract_message or '--'}",
    ]
    if status.warnings:
        lines.append("Warnings: " + "; ".join(status.warnings))
    return "\n".join(lines)


def update_registry_bot(name: str, updates: Dict[str, Any]) -> None:
    schema_block = control_schema_block_reason()
    if schema_block:
        raise RuntimeError(schema_block)
    registry = read_registry()
    bots = registry.setdefault("bots", {})
    if name not in bots or not isinstance(bots[name], dict):
        raise KeyError(f"Bot not found in registry: {name}")
    bots[name].update(updates)
    write_registry(registry)


def toggle_bot_enabled(name: str) -> None:
    schema_block = control_schema_block_reason()
    if schema_block:
        raise RuntimeError(schema_block)
    registry = read_registry()
    bots = registry.setdefault("bots", {})
    if name in bots and isinstance(bots[name], dict):
        enabled = not bool(bots[name].get("enabled", True))
        bots[name]["enabled"] = enabled
        write_registry(registry)
        log_event(f"Control enabled for {name}: {enabled}")


def print_candidate_list(candidates: Sequence[LauncherCandidate], bot_path: Path, role: str) -> None:
    if not candidates:
        print(f"No {role} candidates found.")
        return
    for index, candidate in enumerate(candidates[:20], start=1):
        try:
            display = str(Path(candidate.path).relative_to(bot_path))
        except Exception:
            display = candidate.path
        flag = "BLOCKED" if candidate.blocked else "OK"
        print(f"{index:>2}. [{flag:<7}] score {candidate.score:>4}  {display}")
        print(f"    {', '.join(candidate.reasons[:4])}")


def print_log_candidate_list(candidates: Sequence[LogCandidate], bot_path: Path) -> None:
    if not candidates:
        print("No log candidates found.")
        return
    now = time.time()
    for index, candidate in enumerate(candidates[:20], start=1):
        try:
            display = str(Path(candidate.path).relative_to(bot_path))
        except Exception:
            display = candidate.path
        flag = candidate.tier.upper() if candidate.reliable else "LOW"
        if candidate.mtime is not None and candidate.mtime > now:
            age_label = "FUTURE"
        else:
            age_label = fmt_age(max(0.0, (now - candidate.mtime) / 60.0) if candidate.mtime else None)
        print(
            f"{index:>2}. [{flag:<8}] score {candidate.score:>4} "
            f"age {age_label:<7} {display}"
        )
        details = list(candidate.reasons[:4])
        if candidate.family:
            details.append(f"family={candidate.family}")
        print(f"    {', '.join(details)}")


def profile_bot(cfg: Dict[str, Any], bot_name: str) -> None:
    while True:
        bots = get_bots(cfg, rescan=False)
        bot = bots.get(bot_name)
        if not bot:
            pause("Bot is no longer in the registry.")
            return
        clear_screen()
        print(f"Profile: {bot.name}\n")
        print(f"Start: {bot.launcher or '--'} (manual={bot.launcher_manual}, safe={bot.launcher_safe})")
        print(f"Stop: {bot.stop_launcher or '--'} (manual={bot.stop_launcher_manual})")
        print(f"Heartbeat: {bot.heartbeat_file or 'automatic'} (manual={bot.heartbeat_manual})")
        print(f"Stale threshold: {bot.stale_minutes if bot.stale_minutes is not None else 'global default'} minutes")
        print(f"Category: {bot.category} (manual={bot.category_manual})")
        print("\nActions")
        print("  1 Select start launcher   2 Select stop launcher   3 Select heartbeat/log")
        print("  4 Set stale threshold    5 Set category           6 Reset profile to automatic")
        print("  0 Back")
        choice = input("\nSelect: ").strip().lower()
        folder = Path(bot.path)
        starts, stops = audit_launcher_candidates(folder, cfg)
        if choice == "0":
            return
        if choice == "1":
            clear_screen()
            print_candidate_list(starts, folder, "start")
            token = input("\nSelect a non-blocked candidate number, or Enter to cancel: ").strip()
            if token.isdigit() and 1 <= int(token) <= min(20, len(starts)):
                candidate = starts[int(token) - 1]
                if candidate.blocked:
                    pause("That candidate is blocked because its name looks like stop/build/export/setup work.")
                else:
                    update_registry_bot(
                        bot.name,
                        {
                            "launcher": candidate.path,
                            "launcher_kind": candidate.kind,
                            "launcher_manual": True,
                            "launcher_approved": True,
                            "launcher_safe": True,
                            "launcher_score": candidate.score,
                            "launcher_reason": "manual selection: " + "; ".join(candidate.reasons[:3]),
                        },
                    )
                    clear_runtime_bot(bot.name)
                    pause("Start launcher saved. Existing managed ownership was cleared because the command identity changed.")
        elif choice == "2":
            clear_screen()
            print_candidate_list(stops, folder, "stop")
            token = input("\nSelect a non-blocked candidate number, or Enter to cancel: ").strip()
            if token.isdigit() and 1 <= int(token) <= min(20, len(stops)):
                candidate = stops[int(token) - 1]
                if candidate.blocked:
                    pause("That stop candidate has conflicting terms and was not selected.")
                elif not stop_scope_matches_start(folder, bot.launcher, candidate.path):
                    pause("That stop candidate is in a different nested control scope than the selected start launcher.")
                else:
                    update_registry_bot(
                        bot.name,
                        {
                            "stop_launcher": candidate.path,
                            "stop_launcher_kind": candidate.kind,
                            "stop_launcher_manual": True,
                        },
                    )
                    pause("Stop launcher saved.")
        elif choice == "3":
            candidates = find_log_candidates(folder, cfg, force=True)
            clear_screen()
            print_log_candidate_list(candidates, folder)
            token = input("\nSelect a candidate number, A for automatic, or Enter to cancel: ").strip().lower()
            if token == "a":
                update_registry_bot(bot.name, {"heartbeat_file": "", "heartbeat_manual": False})
                pause("Heartbeat selection returned to automatic scoring.")
            elif token.isdigit() and 1 <= int(token) <= min(20, len(candidates)):
                candidate = candidates[int(token) - 1]
                update_registry_bot(bot.name, {"heartbeat_file": candidate.path, "heartbeat_manual": True})
                pause("Heartbeat/log selection saved. Manual selections are trusted even when their automatic score is low.")
        elif choice == "4":
            token = input("Minutes, or Enter to use global default: ").strip()
            if not token:
                update_registry_bot(bot.name, {"stale_minutes": None})
                pause("Global stale threshold restored.")
            else:
                try:
                    minutes = float(token)
                    if minutes <= 0 or minutes > 10080:
                        raise ValueError
                    update_registry_bot(bot.name, {"stale_minutes": minutes})
                    pause("Stale threshold saved.")
                except ValueError:
                    pause("Enter a number greater than 0 and no more than 10080 minutes.")
        elif choice == "5":
            categories = ["trade", "miner", "utility", "manager", "unknown"]
            print("1 trade   2 miner   3 utility   4 unknown   A automatic")
            token = input("Select: ").strip().lower()
            if token == "a":
                update_registry_bot(bot.name, {"category_manual": False})
                scan_bots(cfg, save=True)
                pause("Category returned to automatic classification.")
            elif token in {"1", "2", "3", "4"}:
                update_registry_bot(bot.name, {"category": categories[int(token) - 1], "category_manual": True})
                pause("Category saved.")
        elif choice == "6":
            if confirm_action("Reset start, stop, heartbeat, stale threshold, and category selections to automatic detection?", cfg):
                update_registry_bot(
                    bot.name,
                    {
                        "launcher_manual": False,
                        "launcher_approved": False,
                        "stop_launcher_manual": False,
                        "heartbeat_file": "",
                        "heartbeat_manual": False,
                        "stale_minutes": None,
                        "category_manual": False,
                    },
                )
                clear_runtime_bot(bot.name)
                scan_bots(cfg, save=True)
                pause("Profile reset to automatic detection.")
        else:
            pause("Unknown selection.")


def clear_screen() -> None:
    os.system("cls" if is_windows_host() else "clear")


def pause(message: str = "") -> None:
    if message:
        print("\n" + message)
    input("\nPress Enter to continue...")


def bot_menu(cfg: Dict[str, Any], bot_name: str) -> None:
    while True:
        bots = get_bots(cfg, rescan=False)
        bot = bots.get(bot_name)
        if not bot:
            pause("Bot disappeared from the registry.")
            return
        status = status_for_bots(cfg, {bot.name: bot})[0]
        clear_screen()
        print(bot_detail_text(cfg, status))
        print("\nActions")
        print("  S Start                 X Run stop script       F Force-stop managed tree")
        print("  A Adopt observed roots  L Tail health log       P Profile launch/health")
        print("  O Open bot folder       E Enable/disable control B Back")
        choice = input("\nSelect: ").strip().lower()
        if choice in {"b", "back", "q", "quit", "0"}:
            return
        if choice in {"s", "start"}:
            start_bot(bot, cfg)
            pause()
        elif choice in {"x", "stop"}:
            run_stop_script(bot, cfg)
            pause()
        elif choice in {"f", "force"}:
            force_stop_bot(bot, cfg)
            pause()
        elif choice in {"a", "adopt"}:
            adopt_bot(bot, cfg)
            pause()
        elif choice in {"l", "tail"}:
            tail_bot(bot, cfg)
            pause()
        elif choice in {"p", "profile"}:
            profile_bot(cfg, bot.name)
        elif choice in {"o", "open"}:
            open_path(Path(bot.path))
        elif choice in {"e", "enable", "disable"}:
            toggle_bot_enabled(bot.name)
            pause("Control flag toggled. Monitoring remains active even when control is off.")
        else:
            pause("Unknown selection.")


def start_launcher_coverage_required(bot: BotRecord) -> bool:
    if not bot.enabled:
        return False
    if bot.category in {"trade", "miner"}:
        return True
    if bot.category in {"utility", "manager"}:
        return False
    # Unknown folders with "bot" in the project name are more likely to be
    # intentionally managed automation; pure utilities stay monitor-only.
    return "bot" in compact_name(bot.name)


def run_selftest(cfg: Dict[str, Any], bots: Optional[Dict[str, BotRecord]] = None, *, persist: bool = True) -> Dict[str, Any]:
    bots = bots if bots is not None else get_bots(cfg, rescan=False)
    checks: List[Dict[str, str]] = []

    def add(name: str, status: str, detail: str) -> None:
        checks.append({"name": name, "status": status, "detail": detail})

    version_ok = sys.version_info >= (3, 10)
    add("Python runtime", "PASS" if version_ok else "FAIL", sys.version.splitlines()[0])
    root = Path(str(cfg.get("bots_root", DEFAULT_BOTS_ROOT)))
    add("Bots root", "PASS" if root.exists() else "FAIL", f"source={cfg.get('_bots_root_source', 'unknown')} path={root}")
    targeting = build_path_targeting_report(cfg, bots)
    path_findings = targeting.get("findings") or []
    add(
        "Path targeting guard",
        "WARN" if path_findings and root.exists() else "FAIL" if path_findings else "PASS",
        "; ".join(path_findings) if path_findings else "root source/provenance and relocation guard look usable",
    )
    if not persist or manager_state_is_read_only():
        # Diagnostic export must not create even a temporary state probe. This
        # is a non-mutating capability hint; the normal interactive self-test
        # below remains the authoritative write check.
        writable_hint = state_dir().exists() and os.access(state_dir(), os.W_OK)
        add(
            "State directory writable",
            "PASS" if writable_hint else "WARN",
            f"non-mutating report-only check: {state_dir()}",
        )
    else:
        try:
            probe = state_dir() / f".write_probe_{os.getpid()}"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            add("State directory writable", "PASS", str(state_dir()))
        except Exception as exc:
            add("State directory writable", "FAIL", str(exc))
    if config_path().exists():
        try:
            json.loads(config_path().read_text(encoding="utf-8"))
            add("Config JSON", "PASS", str(config_path()))
        except Exception as exc:
            add("Config JSON", "FAIL", str(exc))
    elif not persist or manager_state_is_read_only():
        add(
            "Config JSON",
            "WARN",
            "config file is absent; effective defaults are in memory and report-only mode did not create state",
        )
    else:
        add("Config JSON", "FAIL", f"missing after normal config load: {config_path()}")
    try:
        registry = read_registry()
        add("Registry JSON", "PASS", f"{len(registry.get('bots', {}))} entries")
    except Exception as exc:
        add("Registry JSON", "FAIL", str(exc))
    control_schema_warnings = control_state_schema_warnings()
    add(
        "Control state schema compatibility",
        "FAIL" if control_schema_warnings else "PASS",
        "; ".join(control_schema_warnings) if control_schema_warnings else "config, registry, and runtime state schema versions are supported",
    )
    health_newer = schema_newer_than(health_state_path(), HEALTH_STATE_VERSION)
    if health_newer is not None:
        add(
            "Health state schema compatibility",
            "WARN",
            f"schema version {health_newer} is newer than supported {HEALTH_STATE_VERSION}; adaptive learning is disabled and the file is untouched",
        )
    else:
        try:
            health_state = read_health_state()
            learned_bots = len(health_state.get("bots", {})) if isinstance(health_state.get("bots"), dict) else 0
            add(
                "Health state schema compatibility",
                "PASS",
                f"schema version {HEALTH_STATE_VERSION}; bounded learning records={learned_bots}",
            )
        except Exception as exc:
            add("Health state schema compatibility", "WARN", str(exc))
    add(
        "Health evidence engine",
        "PASS",
        "enabled={} min_samples={} max_threshold_factor={} stale_confirmations={} hard_stale_factor={}".format(
            bool(cfg.get("adaptive_health_enabled", True)),
            int(cfg.get("adaptive_health_min_samples", 5)),
            float(cfg.get("adaptive_health_max_threshold_factor", 6.0)),
            int(cfg.get("health_stale_confirmations", 2)),
            float(cfg.get("health_hard_stale_factor", 2.0)),
        ),
    )
    add(
        "Structured health contract",
        "PASS",
        f"optional schema={HEALTH_CONTRACT_SCHEMA}; bounded local JSON <= {int(cfg.get('health_contract_max_bytes', 65536))} bytes; auto-detect paths={len(HEALTH_CONTRACT_RELATIVE_PATHS)}; monitor-only",
    )
    control_lock = read_control_action_lock()
    add(
        "Control action lock",
        "WARN" if control_lock.get("active") else "PASS",
        f"active action={control_lock.get('action', '?')} bot={control_lock.get('bot_name', '?')} age_seconds={control_lock.get('age_seconds', '?')}" if control_lock.get("active") else "no active start/stop/adopt/force-stop lock",
    )
    if is_windows_host():
        shell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
        add("PowerShell/CIM process scan", "PASS" if shell else "FAIL", shell or "not found")
    else:
        add("Windows host", "WARN", f"Current platform is {sys.platform}; start/stop integration is Windows-only")
    processes = get_processes(cfg, force=True)
    add("Process inventory", "PASS" if processes else "WARN", f"{len(processes)} process records")
    if is_windows_host():
        timestamped = sum(1 for process in processes if process.creation_time is not None)
        add(
            "Process identity timestamps",
            "PASS" if timestamped else "FAIL",
            f"{timestamped} of {len(processes)} records include CreationDate",
        )
        current = next((process for process in processes if process.pid == os.getpid()), None)
        add(
            "Process inventory integrity",
            "PASS" if process_inventory_reliable(processes) else "FAIL",
            "manager PID and CreationDate verified" if current and current.creation_time is not None else "manager PID/CreationDate missing; control actions will be blocked",
        )

    unsafe_selected = [bot.name for bot in bots.values() if bot.launcher and not bot.launcher_safe]
    add(
        "Launcher safety",
        "PASS" if not unsafe_selected else "FAIL",
        "No blocked launcher selected" if not unsafe_selected else "Blocked/unapproved: " + ", ".join(unsafe_selected),
    )
    no_launcher = [bot.name for bot in bots.values() if not bot.launcher and start_launcher_coverage_required(bot)]
    add(
        "Start launcher coverage",
        "WARN" if no_launcher else "PASS",
        "Missing safe start launcher: " + (", ".join(no_launcher) if no_launcher else "none"),
    )
    location = install_location_warning()
    add("Install location", "WARN" if location else "PASS", location or str(app_root()))
    assurance = config_input_assurance(cfg)
    config_findings = assurance.get("findings", [])
    unknown_keys = assurance.get("unknown_keys", [])
    add(
        "Config input assurance",
        "WARN" if config_findings or unknown_keys else "PASS",
        (
            f"unknown_keys={unknown_keys or 'none'}; findings={config_findings or 'none'}; "
            "unknown keys are preserved and reported"
        ),
    )
    add(
        "PowerShell execution-policy boundary",
        "PASS" if not cfg.get("powershell_execution_policy_bypass", False) else "FAIL",
        "BotOps never adds -ExecutionPolicy Bypass; blocked scripts require user-approved repair/signing/policy handling",
    )
    norton_status = build_norton_status(cfg)
    add(
        "Norton-compatible runtime boundary",
        "PASS",
        "no security-setting changes, exclusions, packers, persistence install, runtime download-and-execute, or execution-policy bypass; exact final-artifact Norton-on test remains external",
    )
    source_hash = sha256_file(Path(__file__))
    add("Manager source hash", "PASS", source_hash)
    asset_metadata = build_asset_metadata_reconciliation()
    metadata_summary = asset_metadata.get("summary", {})
    add(
        "Asset metadata reconciliation",
        str(asset_metadata.get("status", "WARN")),
        (
            f"schema={ASSET_MANIFEST_SCHEMA}; records={metadata_summary.get('manifest_records', 0)}; "
            f"missing={metadata_summary.get('missing_count', 0)}; stale={metadata_summary.get('stale_count', 0)}; "
            f"conflicts={metadata_summary.get('conflict_count', 0)}; header_gaps={metadata_summary.get('header_gap_count', 0)}; "
            f"unsupported={metadata_summary.get('unsupported_count', 0)}"
        ),
    )

    overall = "FAIL" if any(item["status"] == "FAIL" for item in checks) else "WARN" if any(item["status"] == "WARN" for item in checks) else "PASS"
    result = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "parameter_baseline": PARAMETER_BASELINE,
        "created_at": utc_stamp(),
        "overall": overall,
        "norton_status": norton_status,
        "asset_metadata_reconciliation": asset_metadata,
        "config_input_assurance": assurance,
        "checks": checks,
    }
    if persist:
        try:
            write_json(last_selftest_path(), result, backup=False)
        except Exception as exc:
            log_event(f"Could not save self-test result: {exc}", "WARNING")
    return result


def selftest_text(result: Dict[str, Any]) -> str:
    lines = [f"{APP_NAME} v{APP_VERSION} preflight/self-test: {result.get('overall', 'UNKNOWN')}", ""]
    for check in result.get("checks", []):
        lines.append(f"[{check.get('status', '?'):<4}] {check.get('name', '')}: {check.get('detail', '')}")
    return "\n".join(lines)


def acquire_watch_lock(cfg: Dict[str, Any]) -> Optional[Path]:
    lock_path = state_dir() / "watch.pid"
    processes = get_processes(cfg, force=True)
    inventory_reliable = process_inventory_reliable(processes)
    by_pid = {process.pid: process for process in processes}
    if lock_path.exists():
        if is_windows_host() and not inventory_reliable:
            # Fail closed: without a trustworthy inventory, an existing lock
            # cannot safely be declared stale.
            return None
        try:
            raw = json.loads(lock_path.read_text(encoding="utf-8"))
            pid = int(raw.get("pid") or 0)
            process = by_pid.get(pid)
            expected_created = parse_process_time(raw.get("process_created_at_epoch"))
            if process is not None:
                same_identity = bool(
                    expected_created is not None
                    and process.creation_time is not None
                    and abs(expected_created - process.creation_time) <= 4
                )
                legacy_match = expected_created is None and normalize_text_path(str(app_root())) in process.searchable_text
                if same_identity or legacy_match:
                    return None
        except Exception:
            pass
        try:
            lock_path.unlink(missing_ok=True)
        except Exception:
            return None
    try:
        current = by_pid.get(os.getpid())
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(
            fd,
            json.dumps(
                {
                    "pid": os.getpid(),
                    "created_at": utc_stamp(),
                    "process_created_at_epoch": current.creation_time if current else None,
                }
            ).encode("utf-8"),
        )
        os.close(fd)
        return lock_path
    except Exception:
        return None


def watch_dashboard(cfg: Dict[str, Any], interval: Optional[int] = None) -> None:
    lock_path = acquire_watch_lock(cfg)
    if lock_path is None:
        print("Another live dashboard appears to be running. Close it or remove state\\watch.pid after confirming it is stale.")
        return
    interval_value = max(2, int(interval if interval is not None else cfg.get("watch_interval_seconds", 10)))
    rescan_seconds = max(interval_value, int(cfg.get("watch_rescan_seconds", 120)))
    watch_cfg = copy.deepcopy(cfg)
    # Cadence learning must use the actual observation interval, including a
    # one-off CLI --interval override, or legitimate samples would be discarded
    # as monitoring gaps.
    watch_cfg["watch_interval_seconds"] = interval_value
    last_scan = 0.0
    print("Live dashboard. Press Ctrl+C to return.")
    try:
        while True:
            now = time.monotonic()
            rescan = now - last_scan >= rescan_seconds
            if rescan:
                scan_bots(cfg, save=True)
                last_scan = now
            clear_screen()
            print_dashboard(watch_cfg, rescan=False)
            print(f"\nRefresh: {interval_value}s | folder rescan: {rescan_seconds}s | Ctrl+C returns")
            time.sleep(interval_value)
    except KeyboardInterrupt:
        return
    finally:
        try:
            lock_path.unlink(missing_ok=True)
        except Exception:
            pass


def relative_sanitized_path(value: str, cfg: Dict[str, Any]) -> str:
    text = str(value)
    replacements: List[Tuple[str, str]] = [
        (str(app_root()), "<APP_ROOT>"),
        (str(Path(str(cfg.get("bots_root", DEFAULT_BOTS_ROOT)))), "<BOTS_ROOT>"),
        (str(Path.home()), "<USER_HOME>"),
    ]
    for original, replacement in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        if original:
            text = re.sub(re.escape(original), replacement, text, flags=re.IGNORECASE)
            text = re.sub(re.escape(original.replace("\\", "/")), replacement, text, flags=re.IGNORECASE)
    return redact(text)


def sensitive_diagnostic_key(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(key).strip().lower()).strip("_")
    if normalized in SENSITIVE_DIAGNOSTIC_KEYS:
        return True
    return any(normalized.endswith("_" + item) for item in SENSITIVE_DIAGNOSTIC_KEYS)


def sanitize_for_diagnostics(value: Any, cfg: Dict[str, Any]) -> Any:
    if isinstance(value, dict):
        sanitized: Dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if sensitive_diagnostic_key(key_text) and not isinstance(item, (bool, int, float, type(None))):
                if item == "" or item == b"":
                    sanitized[key_text] = ""
                else:
                    sanitized[key_text] = "***REDACTED_PRESENT***"
            else:
                sanitized[key_text] = sanitize_for_diagnostics(item, cfg)
        return sanitized
    if isinstance(value, list):
        return [sanitize_for_diagnostics(item, cfg) for item in value]
    if isinstance(value, tuple):
        return [sanitize_for_diagnostics(item, cfg) for item in value]
    if isinstance(value, str):
        return relative_sanitized_path(value, cfg)
    return value


def build_environment_snapshot(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Return a compact, redacted runtime snapshot for diagnostics."""
    tool_names = ["py.exe", "python.exe", "python", "powershell.exe", "pwsh.exe", "wt.exe", "cmd.exe"]
    tools: Dict[str, str] = {}
    for tool in tool_names:
        found = shutil.which(tool)
        tools[tool] = relative_sanitized_path(found, cfg) if found else "not_found"
    return {
        "platform": sys.platform,
        "os_name": os.name,
        "is_windows_host": is_windows_host(),
        "python_version": sys.version.splitlines()[0],
        "python_executable": relative_sanitized_path(sys.executable, cfg),
        "current_working_directory": relative_sanitized_path(os.getcwd(), cfg),
        "app_root": relative_sanitized_path(str(app_root()), cfg),
        "bots_root": relative_sanitized_path(str(cfg.get("bots_root", DEFAULT_BOTS_ROOT)), cfg),
        "bots_root_source": str(cfg.get("_bots_root_source", "unknown")),
        "path_targeting": build_path_targeting_report(cfg),
        "path_tools": tools,
        "timezone_chicago": chicago_now().isoformat(timespec="seconds"),
    }


def build_norton_status(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Return explicit release/provenance evidence without claiming an AV scan."""
    source = Path(__file__)
    source_hash = sha256_file(source) if source.exists() else "unavailable"
    findings = config_input_assurance(cfg)
    return {
        "schema": NORTON_STATUS_SCHEMA,
        "parameter_baseline": PARAMETER_BASELINE,
        "artifact": f"BotOps_Manager_v{APP_VERSION}.zip",
        "artifact_sha256": "see external release SHA256 sidecar",
        "product": APP_NAME,
        "version": APP_VERSION,
        "publisher": PRODUCT_PUBLISHER,
        "source_sha256": source_hash,
        "signature": {
            "status": "not_signed_source_distribution",
            "verified": False,
            "note": "The release contains source, BAT, tests, and documentation; no EXE/MSI/MSIX is bundled.",
        },
        "packaging_flags": {
            "format": "zip_source_distribution",
            "compiled_binary_included": False,
            "installer_included": False,
            "packer_or_obfuscation": False,
            "runtime_download_and_execute": False,
            "persistence_installation": False,
            "security_setting_changes": False,
            "execution_policy_bypass": False,
            "automatic_exclusions": False,
        },
        "host_validation": {
            "current_host_is_windows": is_windows_host(),
            "exact_final_artifact_norton_on_test": "not_recorded_by_runtime",
            "result": "manual_external_validation_required",
            "note": "BotOps does not inspect or change Norton settings. Test the exact release ZIP on Windows with current Norton protection enabled and no new exclusions.",
        },
        "detection": {
            "status": "none_reported_in_runtime_config",
            "name": "",
            "alert_id": "",
        },
        "submission_status": "not_submitted_or_not_recorded",
        "config_security_findings": findings.get("findings", []),
        "unresolved_risk": "Unsigned BAT/Python automation can still trigger reputation or behavior heuristics; the SHA256 sidecar proves identity, not antivirus acceptance.",
    }


def diagnostic_trace_start() -> Dict[str, Any]:
    now_chicago = chicago_now().isoformat(timespec="seconds")
    return {
        "schema": "diagnostic_operation_trace_v1",
        "run_id": RUN_ID,
        "clock_sources": {"wall": "UTC/system wall clock", "duration": "time.monotonic"},
        "started_at_utc": utc_stamp(),
        "started_at_chicago": now_chicago,
        "last_progress_at_utc": utc_stamp(),
        "last_successful_step": "trace_initialized",
        "steps": [],
        "_started_monotonic": time.monotonic(),
    }


def diagnostic_collect(
    trace: Dict[str, Any],
    name: str,
    collector: Any,
    fallback: Any,
) -> Any:
    """Run one local diagnostic collector and isolate noncritical failure."""
    started_at = utc_stamp()
    started = time.monotonic()
    status = "ok"
    error = ""
    try:
        value = collector()
    except Exception as exc:
        status = "error"
        error = redact(str(exc))
        value = fallback() if callable(fallback) else copy.deepcopy(fallback)
        log_event(f"Diagnostic collector failed: {name}: {error}", "WARNING")
    elapsed = max(0.0, time.monotonic() - started)
    step = {
        "name": name,
        "status": status,
        "started_at_utc": started_at,
        "elapsed_seconds": round(elapsed, 6),
    }
    if error:
        step["error"] = error
    trace.setdefault("steps", []).append(step)
    trace["last_progress_at_utc"] = utc_stamp()
    if status == "ok":
        trace["last_successful_step"] = name
    return value


def diagnostic_trace_finish(
    trace: Dict[str, Any],
    *,
    terminal_status: str,
    shutdown_reason: str,
) -> Dict[str, Any]:
    finished = copy.deepcopy(trace)
    started = float(finished.pop("_started_monotonic", time.monotonic()))
    finished["ended_at_utc"] = utc_stamp()
    finished["ended_at_chicago"] = chicago_now().isoformat(timespec="seconds")
    finished["elapsed_seconds"] = round(max(0.0, time.monotonic() - started), 6)
    finished["terminal_status"] = terminal_status
    finished["shutdown_reason"] = shutdown_reason
    steps = finished.get("steps", []) if isinstance(finished.get("steps"), list) else []
    finished["slowest_major_steps"] = sorted(
        (
            {
                "name": str(step.get("name", "unknown")),
                "elapsed_seconds": float(step.get("elapsed_seconds", 0.0)),
                "status": str(step.get("status", "unknown")),
            }
            for step in steps
            if isinstance(step, dict)
        ),
        key=lambda item: item["elapsed_seconds"],
        reverse=True,
    )[:5]
    finished["collector_failure_count"] = sum(
        1 for step in steps if isinstance(step, dict) and step.get("status") != "ok"
    )
    finished["retry_summary"] = "Local metadata collectors do not retry; atomic ZIP publish retries bounded replace operations up to five times."
    return finished


def build_diagnostic_work_window_exit(
    selftest: Dict[str, Any],
    finished_trace: Dict[str, Any],
    diagnostic: Dict[str, Any],
    omissions: Sequence[str],
    *,
    fallback_used: bool,
) -> Dict[str, Any]:
    """Prepare truthful pre-publication exit evidence for this diagnostic run."""
    steps = finished_trace.get("steps", []) if isinstance(finished_trace.get("steps"), list) else []
    failures = [
        {
            "name": str(step.get("name", "unknown")),
            "status": str(step.get("status", "unknown")),
            "error": str(step.get("error", "")),
        }
        for step in steps
        if isinstance(step, dict) and step.get("status") != "ok"
    ]
    metadata_status = str(diagnostic.get("asset_metadata_reconciliation", {}).get("status", "unavailable"))
    selftest_status = str(selftest.get("overall", "UNAVAILABLE")) if isinstance(selftest, dict) else "UNAVAILABLE"
    verified = [
        "report-only collectors completed with an operation trace",
        f"source asset metadata reconciliation status={metadata_status}",
        f"self-test snapshot status={selftest_status}",
        "Export20 entry plan prepared with explicit omissions",
    ]
    unverified_or_rushed: List[str] = []
    deferred: List[str] = []
    if sys.platform != "win32":
        deferred.append("live Windows start/stop/adopt/force-stop integration was not exercised on this host")
    deferred.append("exact final release ZIP and extracted-file Norton-on validation remains a manual Windows check")
    deferred.append("Google Drive upload and label/description mirroring were not performed by the local program")
    if fallback_used:
        unverified_or_rushed.append("advanced diagnostic plan failed; bounded minimal fallback bundle was used")
    if metadata_status != "PASS":
        unverified_or_rushed.append(f"source asset metadata reconciliation requires review: {metadata_status}")
    if selftest_status not in {"PASS", "WARN"}:
        unverified_or_rushed.append(f"self-test snapshot was not usable: {selftest_status}")
    if omissions:
        deferred.extend(f"Export20 omission: {item}" for item in list(omissions)[:20])
    timeout_failures = [item for item in failures if "timeout" in item.get("error", "").lower()]
    other_failures = [item for item in failures if item not in timeout_failures]
    terminal = str(finished_trace.get("terminal_status", "unknown"))
    return {
        "schema": "diagnostic_work_window_exit_v1",
        "record_scope": "collector and plan status captured before atomic ZIP publication; the adjacent SHA256 sidecar is authoritative for final archive identity",
        "triage": {
            "critical": "report-only behavior, redaction, path/process safety, and evidence preservation",
            "high": "asset metadata reconciliation, Export20 integrity plan, operation trace, and recovery evidence",
            "normal": "environment, launcher, health, and source inventory summaries",
            "optional": "Drive metadata mirroring and external antivirus/signature evidence",
        },
        "status": (
            "completed_verified_with_external_limits"
            if not failures and not fallback_used and not unverified_or_rushed
            else "completed_with_reported_limits"
        ),
        "terminal_status": terminal,
        "completed_verified": verified,
        "completed_unverified_or_rushed": unverified_or_rushed,
        "deferred_skipped_blocked": deferred,
        "actual_tool_timeouts": timeout_failures,
        "actual_errors": other_failures,
        "timeout_statement": (
            f"{len(timeout_failures)} collector timeout(s) were observed and recorded."
            if timeout_failures
            else "No tool timeout was observed during this local diagnostic run."
        ),
        "planned_outputs": [
            str(diagnostic.get("asset_metadata", {}).get("path", "diagnostic ZIP")),
            str(diagnostic.get("asset_metadata", {}).get("hash_delivery", "adjacent SHA256 metadata sidecar")),
        ],
        "next_safe_pass": "On Windows, run preflight, launcher audit, dashboard/watch, and Export20; preserve exact error text and the newest diagnostic ZIP plus its SHA256 sidecar.",
    }


def build_source_package_inventory(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """List packaged source assets, hashes, and canonical IDs without runtime folders."""
    root = app_root()
    limit = max(10, min(250, int(cfg.get("diagnostic_source_inventory_file_limit", 40))))
    entries: List[Dict[str, Any]] = []
    omitted = 0
    metadata_index = manifest_asset_index(root)
    try:
        files = retained_source_files(root)
    except Exception as exc:
        return {"status": "error", "error": redact(str(exc)), "files": [], "omitted_count": 0}
    for path in files:
        rel = path.relative_to(root).as_posix()
        if len(entries) >= limit:
            omitted += 1
            continue
        try:
            stat = path.stat()
            digest = sha256_file(path)
            metadata = metadata_index.get(rel, {})
            entries.append(
                {
                    "path": rel,
                    "asset_id": metadata.get("asset_id", "unindexed"),
                    "role": metadata.get("role", "unindexed"),
                    "status": metadata.get("status", "unindexed"),
                    "sensitivity": metadata.get("sensitivity", "unindexed"),
                    "size_bytes": stat.st_size,
                    "sha256": digest,
                }
            )
        except Exception as exc:
            entries.append({"path": rel, "error": redact(str(exc))})
    return {
        "status": "ok",
        "schema": ASSET_METADATA_SCHEMA,
        "manifest_schema": ASSET_MANIFEST_SCHEMA,
        "file_count": len(entries),
        "omitted_count": omitted,
        "unindexed_count": sum(1 for item in entries if item.get("asset_id") == "unindexed"),
        "files": entries,
    }



def ledger_item_status(status: BotStatus, root_text: str) -> Tuple[str, List[str]]:
    """Return an omission-control state for one discovered bot/profile."""
    reasons: List[str] = []
    bot_path = str(status.bot.path or "")
    if root_text and not path_text_within(root_text, bot_path):
        reasons.append("path outside effective bots_root")
    if status.bot.launcher and not status.bot.launcher_safe:
        reasons.append("selected launcher is not marked safe")
    if status.status.startswith("UNKNOWN"):
        reasons.append("process inventory/status unknown")
    if status.bot.category in {"trade", "miner"} and not status.bot.launcher:
        reasons.append("trade/miner folder has no safe start launcher")
    if status.control_state.startswith("OBSERVED"):
        reasons.append("running process is monitor-only until explicitly adopted")
    if status.status in {"RUNNING/NO_HEARTBEAT", "RUNNING/SUSPECT", "RUNNING/STALE", "RUNNING/TIME_SKEW"}:
        reasons.append("runtime progress evidence is missing, suspect, stale, or time-skewed")
    if status.status in {"RUNNING/UNHEALTHY", "RUNNING/DEGRADED", "RUNNING/NOT_READY", "FAILED/CONTRACT"}:
        reasons.append("structured health contract reports unhealthy, degraded, not-ready, or failed state")
    if status.health_contract_errors:
        reasons.append("structured health contract failed validation")
    if status.status.startswith("START_FAILED"):
        reasons.append("start wrapper did not produce expected runtime child")
    if status.warnings:
        reasons.extend(status.warnings[:4])

    if any("not marked safe" in item or "unknown" in item.lower() or "outside" in item for item in reasons):
        return "blocked_or_unknown", reasons
    if any("no safe start" in item or "monitor-only" in item or "heartbeat" in item or "progress evidence" in item or "structured health contract" in item or "START_FAILED" in item for item in reasons):
        return "needs_review", reasons
    return "verified", reasons


def build_omission_control_ledger(
    cfg: Dict[str, Any],
    statuses: Sequence[BotStatus],
    selftest: Optional[Dict[str, Any]] = None,
    export_omissions: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Compact coverage ledger so broad reviews can see what was checked or skipped."""
    root_text = str(cfg.get("bots_root", DEFAULT_BOTS_ROOT)).strip() or DEFAULT_BOTS_ROOT
    limit = max(20, min(500, int(cfg.get("diagnostic_coverage_ledger_item_limit", 200))))
    root_report = build_path_targeting_report(cfg, {status.bot.name: status.bot for status in statuses})
    selftest_checks = selftest.get("checks", []) if isinstance(selftest, dict) else []
    selftest_summary = {
        "overall": selftest.get("overall", "unavailable") if isinstance(selftest, dict) else "unavailable",
        "pass": sum(1 for item in selftest_checks if item.get("status") == "PASS"),
        "warn": sum(1 for item in selftest_checks if item.get("status") == "WARN"),
        "fail": sum(1 for item in selftest_checks if item.get("status") == "FAIL"),
    }
    metadata_reconciliation = (
        selftest.get("asset_metadata_reconciliation", {}) if isinstance(selftest, dict) else {}
    )
    items: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {"verified": 0, "needs_review": 0, "blocked_or_unknown": 0, "omitted_due_to_limit": 0}
    for status in statuses:
        item_state, reasons = ledger_item_status(status, root_text)
        counts[item_state] = counts.get(item_state, 0) + 1
        if len(items) >= limit:
            counts["omitted_due_to_limit"] += 1
            continue
        items.append(
            {
                "item": status.bot.name,
                "category": status.bot.category,
                "coverage_status": item_state,
                "scan_status": status.status,
                "control_state": status.control_state,
                "path": status.bot.path,
                "start_launcher": status.bot.launcher or "not_selected",
                "start_launcher_safe": bool(status.bot.launcher_safe),
                "stop_launcher": status.bot.stop_launcher or "not_selected",
                "health_reliable": bool(status.health_reliable),
                "health_tier": status.health_tier,
                "health_mode": status.health_mode,
                "health_effective_threshold_minutes": status.health_effective_threshold_minutes,
                "health_suspicion": status.health_suspicion,
                "health_sample_count": status.health_sample_count,
                "health_evidence_kind": status.health_evidence_kind,
                "health_contract_state": status.health_contract_state,
                "health_contract_pid_match": status.health_contract_pid_match,
                "health_contract_error_count": len(status.health_contract_errors),
                "reasons": reasons[:8],
            }
        )
    export_omission_list = list(export_omissions or [])
    checklist = [
        {
            "check": "effective bots root resolved",
            "coverage_status": "verified" if root_report.get("exists") else "blocked_or_unknown",
            "evidence": root_report.get("bots_root_source", "unknown"),
        },
        {
            "check": "scan write guard for missing/moved root",
            "coverage_status": "verified",
            "evidence": root_report.get("scan_write_guard", "unknown"),
        },
        {
            "check": "self-test/preflight",
            "coverage_status": "verified" if selftest_summary["overall"] in {"PASS", "WARN"} else "blocked_or_unknown",
            "evidence": selftest_summary,
        },
        {
            "check": "source asset metadata reconciled",
            "coverage_status": (
                "verified" if metadata_reconciliation.get("status") == "PASS" else
                "needs_review" if metadata_reconciliation.get("status") == "WARN" else
                "blocked_or_unknown"
            ),
            "evidence": {
                "schema": metadata_reconciliation.get("schema", ASSET_METADATA_SCHEMA),
                "status": metadata_reconciliation.get("status", "unavailable"),
                "summary": metadata_reconciliation.get("summary", {}),
            },
        },
        {
            "check": "diagnostic export plan capped and reported",
            "coverage_status": "verified",
            "evidence": "export_plan_final in status.json with entry names and omissions",
        },
        {
            "check": "export omissions tracked",
            "coverage_status": "verified" if not export_omission_list else "needs_review",
            "evidence": {"omission_count": len(export_omission_list), "sample": export_omission_list[:10]},
        },
    ]
    return {
        "schema": "omission_control_ledger_v1",
        "generated_at": utc_stamp(),
        "purpose": "Records discovered coverage so broad reviews do not silently claim all/complete without checked or skipped items.",
        "scope": "effective bot root plus BotOps manager diagnostics/export collectors",
        "bots_root": root_report,
        "selftest_summary": selftest_summary,
        "coverage_counts": counts,
        "checklist": checklist,
        "discovered_items_count": len(statuses),
        "discovered_items_limit": limit,
        "discovered_items": items,
        "unchecked_or_unverified_count": counts.get("needs_review", 0) + counts.get("blocked_or_unknown", 0) + counts.get("omitted_due_to_limit", 0),
        "unchecked_or_unverified_items": [item["item"] for item in items if item["coverage_status"] != "verified"][:50],
        "export_omissions": export_omission_list,
    }


def diagnostic_review_summary(statuses: Sequence[BotStatus]) -> str:
    blocked = [status.bot.name for status in statuses if status.bot.launcher and not status.bot.launcher_safe]
    no_launcher = [status.bot.name for status in statuses if not status.bot.launcher]
    observed = [status.bot.name for status in statuses if status.control_state.startswith("OBSERVED")]
    no_health = [status.bot.name for status in statuses if status.status == "RUNNING/NO_HEARTBEAT"]
    suspect = [status.bot.name for status in statuses if status.status == "RUNNING/SUSPECT"]
    stale = [status.bot.name for status in statuses if status.status == "RUNNING/STALE"]
    clock_skew = [status.bot.name for status in statuses if status.status == "RUNNING/TIME_SKEW"]
    adaptive = [status.bot.name for status in statuses if status.health_mode == "adaptive"]
    start_failed = [status.bot.name for status in statuses if status.status.startswith("START_FAILED")]
    lines = [
        f"{APP_NAME} diagnostic review summary",
        f"Created: {utc_stamp()}",
        "",
        f"Blocked/unapproved selected launchers: {', '.join(blocked) if blocked else 'none'}",
        f"No safe start launcher: {', '.join(no_launcher) if no_launcher else 'none'}",
        f"Observed-only processes: {', '.join(observed) if observed else 'none'}",
        f"Running without reliable progress evidence: {', '.join(no_health) if no_health else 'none'}",
        f"Running with unconfirmed stale evidence: {', '.join(suspect) if suspect else 'none'}",
        f"Running with confirmed stale evidence: {', '.join(stale) if stale else 'none'}",
        f"Running with health timestamp skew: {', '.join(clock_skew) if clock_skew else 'none'}",
        f"Adaptive cadence model active: {', '.join(adaptive) if adaptive else 'none'}",
        f"Start wrapper present without expected runtime: {', '.join(start_failed) if start_failed else 'none'}",
        f"Schema guard warnings: {'; '.join(state_schema_warnings()) if state_schema_warnings() else 'none'}",
        f"Control action lock: {read_control_action_lock().get('action', 'none') if read_control_action_lock().get('active') else 'none'}",
        "",
        "Control safety: force-stop is limited to identity-verified managed/adopted process roots.",
        "Health safety: export/report/diagnostic paths are rejected; cadence learning is bounded and never triggers an automatic restart.",
        "Omission-control ledger: see status.json -> omission_control_ledger for verified/review/blocked coverage.",
        "Work-window exit: see status.json -> work_window_exit for verified, unverified, deferred, error, timeout, and next-pass evidence.",
    ]
    return "\n".join(lines) + "\n"


def cleanup_stale_temp_exports(cfg: Dict[str, Any]) -> None:
    """Remove abandoned temporary diagnostic ZIPs from prior interrupted exports."""
    retention_seconds = max(3600, int(cfg.get("diagnostic_tmp_retention_hours", 24)) * 3600)
    cutoff = time.time() - retention_seconds
    try:
        for path in exports_dir().glob("botops_diagnostic_*.zip.tmp"):
            try:
                stat = path.stat()
                if stat.st_mtime < cutoff:
                    path.unlink(missing_ok=True)
                    log_event(f"Removed stale diagnostic temp archive: {path.name}", "WARNING")
            except Exception as exc:
                log_event(f"Could not clean diagnostic temp archive {path.name}: {exc}", "WARNING")
    except Exception as exc:
        log_event(f"Could not scan diagnostic temp archives: {exc}", "WARNING")


def _dedupe_archive_name(name: str, existing: Set[str]) -> str:
    base = safe_filename(name.replace("\\", "/").lstrip("/"))
    # Preserve folder-style diagnostic names while still removing unsafe characters
    # from individual path components.
    parts = [safe_filename(part) for part in str(name).replace("\\", "/").split("/") if part]
    candidate = "/".join(parts) or base
    stem = candidate
    suffix = ""
    if "." in candidate.rsplit("/", 1)[-1]:
        parent = candidate.rsplit("/", 1)[0] + "/" if "/" in candidate else ""
        filename = candidate.rsplit("/", 1)[-1]
        filename_stem, filename_suffix = filename.rsplit(".", 1)
        stem = parent + filename_stem
        suffix = "." + filename_suffix
    if candidate not in existing:
        existing.add(candidate)
        return candidate
    for index in range(2, 1000):
        candidate_indexed = f"{stem}_{index}{suffix}"
        if candidate_indexed not in existing:
            existing.add(candidate_indexed)
            return candidate_indexed
    raise RuntimeError(f"Could not deduplicate archive entry name: {name}")


def build_diagnostic_export_plan(
    cfg: Dict[str, Any],
    statuses: Sequence[BotStatus],
    selftest: Dict[str, Any],
    dashboard: str,
    launcher_audit: Dict[str, Any],
    health_audit: Dict[str, Any],
    diagnostic: Dict[str, Any],
    manager_tail: str,
) -> Tuple[List[Tuple[str, bytes]], List[str]]:
    """Build a deterministic, capped Export20 plan before opening the ZIP."""
    max_files = max(12, min(20, int(cfg.get("diagnostic_max_files", 20))))
    plan: List[Tuple[str, bytes]] = []
    names: Set[str] = set()
    omissions: List[str] = []

    def add_text(arcname: str, text: str, *, required: bool = False) -> bool:
        if len(plan) >= max_files:
            message = f"omitted {arcname}: diagnostic_max_files={max_files} reached"
            omissions.append(message)
            if required:
                raise RuntimeError(f"Required diagnostic entry could not fit: {arcname}")
            return False
        clean_name = _dedupe_archive_name(arcname, names)
        safe_text = relative_sanitized_path(text, cfg)
        plan.append((clean_name, safe_text.encode("utf-8", errors="replace")))
        return True

    def upsert_text(arcname: str, text: str) -> None:
        safe_text = relative_sanitized_path(text, cfg).encode("utf-8", errors="replace")
        for index, (name, _) in enumerate(plan):
            if name == arcname:
                plan[index] = (name, safe_text)
                return
        if not add_text(arcname, text, required=True):
            raise RuntimeError(f"Required diagnostic entry could not be added: {arcname}")

    diagnostic["export_contract"] = {
        "style": "Export20",
        "max_files": max_files,
        "atomic_publish": True,
        "integrity_test_before_publish": True,
        "read_only_with_respect_to_child_projects": True,
        "read_only_with_respect_to_manager_state": True,
        "corrupt_state_recovery_suppressed": True,
        "export_refresh_registry_requested": bool(cfg.get("export_refresh_registry", False)),
        "export_refresh_registry_applied": False,
        "child_launchers_or_exports_invoked": False,
        "diagnostics_include_log_content": bool(cfg.get("diagnostics_include_log_content", False)),
        "stale_temp_cleanup_applied": False,
        "only_write_activity": "create current diagnostic temp ZIP, integrity-test it, atomically publish final ZIP, then write its adjacent SHA256 metadata sidecar",
        "asset_metadata_schema": ASSET_METADATA_SCHEMA,
        "embedded_zip_metadata_comment": True,
        "sha256_sidecar_requested": True,
        "source_manifest_reconciliation_included": True,
    }
    vault_paths = drive_vault_paths(cfg)
    diagnostic["drive_vault_reference"] = {
        "status": "metadata_only_manual_upload_ready",
        "root": vault_paths["root"],
        "category": vault_paths["category"],
        "project": vault_paths["project"],
        "project_path": vault_paths["project_path"],
        "latest_build_path": vault_paths["latest_build_path"],
        "chatgpt_ready_path": vault_paths["chatgpt_ready_path"],
        "diagnostics_path": vault_paths["diagnostics_path"],
        "changelog_manifest_path": vault_paths["changelog_manifest_path"],
        "archive_path": vault_paths["archive_path"],
        "expected_subfolders": vault_paths["expected_subfolders"],
        "runtime_dependency": False,
        "upload_status": "not_performed_by_local_program",
        "metadata_mirroring": {
            "status": "not_performed_by_local_program",
            "asset_id": diagnostic.get("asset_metadata", {}).get("asset_id", ""),
            "version": APP_VERSION,
            "lifecycle_status": "current",
            "tags": diagnostic.get("asset_metadata", {}).get("tags", []),
            "fallback_authority": "diagnostic filename plus status.json asset_metadata plus adjacent SHA256 sidecar",
        },
        "notes": "The local BotOps program does not depend on Google Drive. Drive is a handoff/reference layer only; local C:\\Bots folders remain runtime folders.",
        "manual_upload_hint": "Upload the release ZIP and SHA256 sidecar to latest_build_path; place handoff/readme docs in chatgpt_ready_path or docs_runbook_path when useful.",
    }
    diagnostic["data_classification"] = {
        "overall": "project-internal",
        "included_by_default": "project-internal metadata, redacted state summaries, launcher/health audit summaries",
        "excluded_by_default": "secret and sensitive content: bot log bodies, process command lines, credentials, API keys, wallet keys, private tokens, account identifiers",
        "review_note": "Review before sharing because bot folder names can still reveal project intent.",
    }
    diagnostic["norton_status"] = build_norton_status(cfg)
    diagnostic["custom_input_assurance"] = {
        "bots_root": {
            "source": "config/default/--root override",
            "effective_value": relative_sanitized_path(str(cfg.get("bots_root", DEFAULT_BOTS_ROOT)), cfg),
            "status": "recognized_validated_mapped",
            "expected_effect": "scanner limits discovery to bot folders under the configured root",
        },
        "control_mode": {
            "source": "config default enforced at load",
            "effective_value": "managed_or_explicitly_adopted_process_roots_only",
            "status": "recognized_validated_mapped",
            "expected_effect": "force-stop cannot target monitor-only external processes",
        },
        "config": config_input_assurance(cfg),
    }
    diagnostic["resource_guardrails"] = {
        "parallel_control_actions": "serialized by project-local control-action lock",
        "diagnostic_max_files": max_files,
        "diagnostic_source_inventory_file_limit": int(cfg.get("diagnostic_source_inventory_file_limit", 40)),
        "diagnostic_coverage_ledger_item_limit": int(cfg.get("diagnostic_coverage_ledger_item_limit", 200)),
        "log_rotation": "2 MB x 3 manager log files",
        "health_learning_bounds": f"{HEALTH_SAMPLE_WINDOW} intervals per bot; static threshold can only widen up to configured factor; no automatic restart action",
        "queue_backpressure": "not applicable; BotOps is a low-volume local manager without producer/consumer queues",
    }
    diagnostic["omission_control_ledger"] = build_omission_control_ledger(cfg, statuses, selftest, [])

    add_text(
        "README_DIAGNOSTIC.txt",
        textwrap.dedent(
            f"""
            {APP_NAME} diagnostic export
            Asset metadata: ID {diagnostic.get('asset_metadata', {}).get('asset_id', '')}; family {DIAGNOSTIC_ASSET_FAMILY_ID}; version {APP_VERSION}; status current; sensitivity project-internal; tags botops-manager,diagnostic,export20,asset-metadata.
            Created UTC: {diagnostic['created_at']}
            Created Chicago: {chicago_now().isoformat(timespec='seconds')}
            Run ID: {RUN_ID}

            This export excludes bot log contents by default, avoids command lines,
            redacts contextual secrets, and tokenizes user/bot-manager root paths.
            It never invokes child bot launchers, export BAT files, maintenance scripts,
            exchange APIs, or other project code. It does not migrate, repair, rename,
            clean, or rewrite prior manager state/export evidence. The current archive
            is staged to a temporary ZIP, integrity-tested, capped to Export20, and
            atomically published.

            Review before sharing because bot folder names can still be sensitive.
            """
        ).strip()
        + "\n",
        required=True,
    )
    add_text("REVIEW_SUMMARY.txt", diagnostic_review_summary(statuses), required=True)
    add_text("dashboard.txt", dashboard + "\n", required=True)
    add_text("status.json", json.dumps(sanitize_for_diagnostics(diagnostic, cfg), indent=2) + "\n", required=True)
    add_text("launcher_audit.json", json.dumps(sanitize_for_diagnostics(launcher_audit, cfg), indent=2) + "\n", required=True)
    add_text("health_audit.json", json.dumps(sanitize_for_diagnostics(health_audit, cfg), indent=2) + "\n", required=True)
    add_text("selftest.json", json.dumps(sanitize_for_diagnostics(selftest, cfg), indent=2) + "\n", required=True)
    add_text("bot_manager_config.json", json.dumps(sanitize_for_diagnostics(cfg, cfg), indent=2) + "\n", required=True)
    add_text("bot_registry.json", json.dumps(sanitize_for_diagnostics(read_registry(), cfg), indent=2) + "\n", required=True)
    add_text("runtime_state.json", json.dumps(sanitize_for_diagnostics(read_runtime_state(), cfg), indent=2) + "\n", required=True)
    add_text("bot_manager_log_tail.txt", manager_tail + "\n", required=True)

    source_docs = [
        "README_RUN_FIRST.md",
        "CHANGELOG.md",
        "KNOWN_GOOD_STATE.md",
        "TRANSFER_BRIEF.md",
        "DEEP_CHECK_REPORT.md",
        "FULL_BATCH_OUTPUT.md",
        "MANIFEST.json",
        "MANIFEST.csv",
    ]
    for filename in source_docs:
        source = app_root() / filename
        if not source.exists():
            omissions.append(f"omitted {filename}: source file not present")
            continue
        try:
            add_text(filename, source.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            omissions.append(f"omitted {filename}: {exc}")

    if cfg.get("diagnostics_include_log_content", False):
        remaining = int(cfg.get("diagnostic_log_file_limit", 3))
        for status in statuses:
            if remaining <= 0 or len(plan) >= max_files:
                break
            health = select_health_candidate(status.bot, cfg)
            if health is None:
                continue
            source = Path(health.path)
            arcname = f"bot_log_tails/{safe_filename(status.bot.name)}_{safe_filename(source.name)}.txt"
            try:
                if add_text(arcname, tail_file(source, lines=120)):
                    remaining -= 1
            except Exception as exc:
                omissions.append(f"omitted {arcname}: {exc}")

    if omissions:
        # Prefer putting omissions into an existing required entry over adding a
        # separate file that would pressure the Export20 cap.
        summary_name = next((idx for idx, (name, _) in enumerate(plan) if name == "REVIEW_SUMMARY.txt"), None)
        if summary_name is not None:
            text = plan[summary_name][1].decode("utf-8", errors="replace")
            text += "\nExport omissions / notes:\n" + "\n".join(f"- {item}" for item in omissions) + "\n"
            plan[summary_name] = (plan[summary_name][0], text.encode("utf-8", errors="replace"))

    diagnostic["omission_control_ledger"] = build_omission_control_ledger(cfg, statuses, selftest, omissions)
    diagnostic["export_plan_final"] = {
        "entry_count": len(plan),
        "entry_names": [name for name, _ in plan],
        "max_files": max_files,
        "omission_count": len(omissions),
        "omissions": list(omissions),
        "finalized_before_zip_open": True,
    }
    upsert_text("status.json", json.dumps(sanitize_for_diagnostics(diagnostic, cfg), indent=2) + "\n")
    return plan, omissions


def build_minimal_diagnostic_export_plan(
    cfg: Dict[str, Any],
    diagnostic: Dict[str, Any],
    failures: Sequence[str],
    manager_tail: str,
) -> Tuple[List[Tuple[str, bytes]], List[str]]:
    """Create a small handoff even when an advanced export collector fails."""
    max_files = max(12, min(20, int(cfg.get("diagnostic_max_files", 20))))
    failure_list = [redact(str(item)) for item in failures if str(item).strip()]
    omissions = [f"advanced export fallback: {item}" for item in failure_list]
    diagnostic["fallback_bundle"] = {
        "used": True,
        "reason_count": len(failure_list),
        "reasons": failure_list,
        "contents": "current-state summary, sanitized effective config, manager log tail when available, and recovery guidance",
    }
    diagnostic.setdefault(
        "export_contract",
        {
            "style": "Export20-minimal-fallback",
            "max_files": max_files,
            "atomic_publish": True,
            "integrity_test_before_publish": True,
            "read_only_with_respect_to_child_projects": True,
            "read_only_with_respect_to_manager_state": True,
            "stale_temp_cleanup_applied": False,
            "child_launchers_or_exports_invoked": False,
            "asset_metadata_schema": ASSET_METADATA_SCHEMA,
            "embedded_zip_metadata_comment": True,
            "sha256_sidecar_requested": True,
            "source_manifest_reconciliation_included": True,
        },
    )
    review = [
        f"{APP_NAME} minimal diagnostic fallback",
        f"Asset metadata: ID {diagnostic.get('asset_metadata', {}).get('asset_id', '')}; family {DIAGNOSTIC_ASSET_FAMILY_ID}; version {APP_VERSION}; status current; sensitivity project-internal.",
        f"Run ID: {RUN_ID}",
        "",
        "Advanced collection failed, but the exporter preserved a compact report-only handoff.",
        "Failures:",
    ]
    review.extend(f"- {item}" for item in failure_list or ["unspecified advanced collector failure"])
    review.extend(
        [
            "",
            "First recovery step: run option 5 (Preflight / self-test), then option 3 (Rescan + launcher safety audit).",
            "No child bot, exchange/API, Norton setting, execution policy, config migration, or prior evidence was modified.",
        ]
    )
    review_text = "\n".join(review) + "\n"
    plan: List[Tuple[str, bytes]] = [
        ("README_DIAGNOSTIC.txt", review_text.encode("utf-8")),
        ("REVIEW_SUMMARY.txt", review_text.encode("utf-8")),
        (
            "bot_manager_config.json",
            (json.dumps(sanitize_for_diagnostics(cfg, cfg), indent=2) + "\n").encode("utf-8"),
        ),
    ]
    if manager_tail:
        plan.append(
            (
                "bot_manager_log_tail.txt",
                relative_sanitized_path(manager_tail, cfg).encode("utf-8", errors="replace"),
            )
        )
    final_names = [name for name, _ in plan] + ["status.json"]
    diagnostic["export_plan_final"] = {
        "entry_count": len(final_names),
        "entry_names": final_names,
        "max_files": max_files,
        "omission_count": len(omissions),
        "omissions": omissions,
        "finalized_before_zip_open": True,
        "fallback": True,
    }
    plan.append(
        (
            "status.json",
            (json.dumps(sanitize_for_diagnostics(diagnostic, cfg), indent=2) + "\n").encode("utf-8"),
        )
    )
    return plan[:max_files], omissions


def write_atomic_diagnostic_zip(
    export_path: Path,
    plan: Sequence[Tuple[str, bytes]],
    cfg: Dict[str, Any],
    *,
    archive_comment: bytes = b"",
) -> None:
    max_files = max(12, min(20, int(cfg.get("diagnostic_max_files", 20))))
    temp_path = unique_path(export_path.with_name(f"{export_path.stem}.{RUN_ID}.zip.tmp"))
    try:
        with zipfile.ZipFile(temp_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.comment = archive_comment
            for arcname, payload in plan:
                if not arcname or arcname.startswith("/") or ".." in Path(arcname).parts:
                    raise RuntimeError(f"Unsafe diagnostic archive entry name: {arcname}")
                archive.writestr(arcname, payload)
        with zipfile.ZipFile(temp_path, "r") as archive:
            bad_entry = archive.testzip()
            names = archive.namelist()
        if bad_entry:
            raise RuntimeError(f"Diagnostic ZIP integrity test failed at {bad_entry}")
        if len(names) > max_files:
            raise RuntimeError(f"Diagnostic ZIP entry count {len(names)} exceeds configured cap {max_files}")
        last_exc: Optional[Exception] = None
        for attempt in range(5):
            try:
                os.replace(temp_path, export_path)
                return
            except Exception as exc:
                last_exc = exc
                time.sleep(0.08 * (attempt + 1))
        if last_exc:
            raise last_exc
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass


def export_diagnostics(cfg: Dict[str, Any]) -> Path:
    # Enforce the report-only contract even if an unexpected helper attempts a
    # state write or encounters malformed JSON. Nested callers are supported.
    with report_only_state_mode():
        return _export_diagnostics_read_only(cfg)


def _export_diagnostics_read_only(cfg: Dict[str, Any]) -> Path:
    # Export creates only the current temp/final diagnostic ZIP. It does not
    # migrate, repair, rename, clean, or rewrite prior manager/bot evidence.
    trace = diagnostic_trace_start()
    created_chicago = chicago_now()
    export_path = unique_path(exports_dir() / f"botops_diagnostic_v{APP_VERSION}_{local_stamp_for_filename()}.zip")
    export_asset_metadata = diagnostic_asset_metadata(export_path, created=created_chicago)

    bots = diagnostic_collect(trace, "scan_bots_in_memory", lambda: scan_bots(cfg, save=False), {})
    statuses = diagnostic_collect(
        trace,
        "collect_status_without_state_write",
        lambda: status_for_bots(cfg, bots, cleanup_stale=False, persist_health=False),
        [],
    )
    selftest_fallback = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "parameter_baseline": PARAMETER_BASELINE,
        "created_at": utc_stamp(),
        "overall": "UNAVAILABLE",
        "checks": [],
        "error": "self-test collector failed; see operation trace",
    }
    selftest = diagnostic_collect(trace, "run_report_only_selftest", lambda: run_selftest(cfg, bots, persist=False), selftest_fallback)
    dashboard = diagnostic_collect(
        trace,
        "render_dashboard",
        lambda: dashboard_text(cfg, statuses),
        f"{APP_NAME} v{APP_VERSION}\nDashboard unavailable; see status.json operation trace.",
    )

    def collect_bot_audits() -> Tuple[Dict[str, Any], Dict[str, Any], List[str]]:
        launcher_audit: Dict[str, Any] = {}
        health_audit: Dict[str, Any] = {}
        item_errors: List[str] = []
        status_by_name = {status.bot.name: status for status in statuses}
        for bot in bots.values():
            try:
                starts, stops = audit_launcher_candidates(Path(bot.path), cfg)
                launcher_audit[bot.name] = {
                    "selected_start": bot.launcher,
                    "selected_start_safe": bot.launcher_safe,
                    "selected_stop": bot.stop_launcher,
                    "start_candidates": [asdict(candidate) for candidate in starts[:12]],
                    "stop_candidates": [asdict(candidate) for candidate in stops[:12]],
                }
            except Exception as exc:
                error = redact(str(exc))
                item_errors.append(f"launcher audit {bot.name}: {error}")
                launcher_audit[bot.name] = {"status": "error", "error": error}
            try:
                health_candidates = find_log_candidates(Path(bot.path), cfg)
                selected_health = select_health_candidate(bot, cfg, candidates=health_candidates)
                status = status_by_name.get(bot.name)
                health_audit[bot.name] = {
                    "selected_heartbeat": selected_health.path if selected_health else "",
                    "selected_candidate": asdict(selected_health) if selected_health else None,
                    "manual": bot.heartbeat_manual,
                    "configured_manual_heartbeat": bot.heartbeat_file if bot.heartbeat_manual else "",
                    "manual_selection_valid": bool(
                        bot.heartbeat_manual and selected_health and selected_health.tier == "manual"
                    ),
                    "assessment": {
                        "status": status.status if status else "unknown",
                        "tier": status.health_tier if status else "none",
                        "mode": status.health_mode if status else "none",
                        "effective_threshold_minutes": status.health_effective_threshold_minutes if status else None,
                        "suspicion": status.health_suspicion if status else None,
                        "sample_count": status.health_sample_count if status else 0,
                        "evidence_count": status.health_evidence_count if status else 0,
                        "advanced": status.health_advanced if status else False,
                        "clock_skew": status.health_clock_skew if status else False,
                    },
                    "candidates": [asdict(candidate) for candidate in health_candidates[:12]],
                }
            except Exception as exc:
                error = redact(str(exc))
                item_errors.append(f"health audit {bot.name}: {error}")
                health_audit[bot.name] = {"status": "error", "error": error}
        return launcher_audit, health_audit, item_errors

    launcher_audit, health_audit, audit_item_errors = diagnostic_collect(
        trace,
        "collect_launcher_and_health_audits",
        collect_bot_audits,
        ({}, {}, ["launcher/health audit collector failed"]),
    )
    if audit_item_errors and trace.get("steps"):
        trace["steps"][-1]["status"] = "partial"
        trace["steps"][-1]["error"] = "; ".join(audit_item_errors[:8])

    raw_health_snapshot = diagnostic_collect(
        trace,
        "read_health_state_snapshot",
        lambda: raw_json_no_recovery(health_state_path()),
        None,
    )
    health_state_snapshot = raw_health_snapshot if isinstance(raw_health_snapshot, dict) else {
        "version": HEALTH_STATE_VERSION,
        "updated_at": "",
        "bots": {},
        "note": "health state was absent or unreadable; export did not repair or rewrite it",
    }
    environment_snapshot = diagnostic_collect(trace, "collect_environment_snapshot", lambda: build_environment_snapshot(cfg), {"status": "error"})
    source_inventory = diagnostic_collect(trace, "inventory_source_package", lambda: build_source_package_inventory(cfg), {"status": "error", "files": []})
    asset_metadata_reconciliation = diagnostic_collect(
        trace,
        "reconcile_source_asset_metadata",
        build_asset_metadata_reconciliation,
        {"schema": ASSET_METADATA_SCHEMA, "status": "WARN", "manifest_read_status": "collector_failed"},
    )
    path_targeting = diagnostic_collect(trace, "analyze_path_targeting", lambda: build_path_targeting_report(cfg, bots), {"status": "error"})
    schema_warnings = diagnostic_collect(trace, "read_schema_guards", state_schema_warnings, [])
    control_lock = diagnostic_collect(trace, "read_control_action_lock", read_control_action_lock, {"active": False, "status": "unavailable"})
    manager_tail = diagnostic_collect(
        trace,
        "read_manager_log_tail",
        lambda: tail_file(manager_log_path(), lines=250) if manager_log_path().exists() else "",
        "",
    )
    status_payload = diagnostic_collect(trace, "serialize_statuses", lambda: [status_to_dict(status) for status in statuses], [])

    diagnostic: Dict[str, Any] = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "parameter_baseline": PARAMETER_BASELINE,
        "asset_metadata": export_asset_metadata,
        "asset_metadata_reconciliation": asset_metadata_reconciliation,
        "created_at": utc_stamp(),
        "created_at_chicago": created_chicago.isoformat(timespec="seconds"),
        "run_id": RUN_ID,
        "privacy_note": "Bot log contents are excluded by default. Paths are reduced to <APP_ROOT>, <BOTS_ROOT>, and <USER_HOME> tokens.",
        "integration_review": {
            "state": "verified",
            "scope": "local_windows_process_management_only",
            "external_exchange_api_access": False,
            "secret_or_credential_access": False,
            "last_reviewed": "2026-07-18",
            "freshness_target_days": 30,
            "notes": "BotOps does not call exchange APIs, SDKs, webhooks, cloud services, trading endpoints, or child bot export scripts. The v1.13 health engine observes process identity, bounded local file metadata, and optional botops_health_v1 JSON contracts; it never restarts a bot automatically.",
        },
        "control_action_lock": control_lock,
        "platform": sys.platform,
        "python": sys.version,
        "environment_snapshot": environment_snapshot,
        "source_package_inventory": source_inventory,
        "bots_root_exists": Path(str(cfg.get("bots_root", DEFAULT_BOTS_ROOT))).exists(),
        "path_targeting": path_targeting,
        "schema_guard_warnings": schema_warnings,
        "health_state_snapshot": health_state_snapshot,
        "statuses": status_payload,
        "audit_item_errors": audit_item_errors,
    }

    fallback_used = False
    plan_failures: List[str] = []
    plan_started = time.monotonic()
    plan_started_at = utc_stamp()
    try:
        plan, omissions = build_diagnostic_export_plan(
            cfg,
            statuses,
            selftest,
            dashboard,
            launcher_audit,
            health_audit,
            diagnostic,
            manager_tail,
        )
        plan_status = "ok"
        plan_error = ""
    except Exception as exc:
        plan_status = "error"
        plan_error = redact(str(exc))
        plan_failures.append(plan_error)
        fallback_used = True
        plan, omissions = build_minimal_diagnostic_export_plan(cfg, diagnostic, plan_failures, manager_tail)
        log_event(f"Advanced diagnostic plan failed; minimal fallback used: {plan_error}", "WARNING")
    trace.setdefault("steps", []).append(
        {
            "name": "build_export_plan",
            "status": plan_status,
            "started_at_utc": plan_started_at,
            "elapsed_seconds": round(max(0.0, time.monotonic() - plan_started), 6),
            **({"error": plan_error} if plan_error else {}),
        }
    )
    trace["last_progress_at_utc"] = utc_stamp()
    if plan_status == "ok":
        trace["last_successful_step"] = "build_export_plan"

    terminal = "completed_with_fallback" if fallback_used else (
        "completed_with_collector_warnings" if any(step.get("status") != "ok" for step in trace.get("steps", [])) else "completed"
    )
    finished_trace = diagnostic_trace_finish(
        trace,
        terminal_status=terminal,
        shutdown_reason="normal_report_only_export_completion",
    )
    diagnostic["operation_trace"] = finished_trace
    diagnostic["collector_failures"] = [
        {"name": step.get("name"), "status": step.get("status"), "error": step.get("error", "")}
        for step in finished_trace.get("steps", [])
        if step.get("status") != "ok"
    ]
    diagnostic["fallback_bundle_used"] = fallback_used
    diagnostic["work_window_exit"] = build_diagnostic_work_window_exit(
        selftest,
        finished_trace,
        diagnostic,
        omissions,
        fallback_used=fallback_used,
    )

    # The plan builder serializes status.json before the operation trace is
    # final. Replace only that in-memory payload; no prior file is rewritten.
    status_bytes = (json.dumps(sanitize_for_diagnostics(diagnostic, cfg), indent=2) + "\n").encode("utf-8")
    status_index = next((index for index, (name, _) in enumerate(plan) if name == "status.json"), None)
    if status_index is None:
        if len(plan) >= max(12, min(20, int(cfg.get("diagnostic_max_files", 20)))):
            raise RuntimeError("Diagnostic plan has no status.json and no remaining Export20 slot")
        plan.append(("status.json", status_bytes))
    else:
        plan[status_index] = ("status.json", status_bytes)

    write_atomic_diagnostic_zip(
        export_path,
        plan,
        cfg,
        archive_comment=diagnostic_zip_comment(export_asset_metadata),
    )
    sidecar_path: Optional[Path] = None
    try:
        sidecar_path = write_diagnostic_sha256_sidecar(export_path, export_asset_metadata)
    except Exception as exc:
        log_event(f"Diagnostic ZIP created but SHA256 metadata sidecar failed: {exc}", "WARNING")
    log_event(
        f"Diagnostic export created: {export_path} entries={len(plan)} omissions={len(omissions)} "
        f"fallback={fallback_used} sha256_sidecar={sidecar_path or 'unavailable'}"
    )
    return export_path


def interactive_menu(cfg: Dict[str, Any]) -> None:
    get_bots(cfg, rescan=True)
    while True:
        clear_screen()
        bots = get_bots(cfg, rescan=False)
        statuses = status_for_bots(cfg, bots)
        print(dashboard_text(cfg, statuses))
        write_observability_outputs(cfg, statuses)
        print("\nActions")
        print("  [number] Manage bot   R Rescan/safety audit   W Live dashboard   D Export diagnostics")
        print("  P Preflight/self-test O Open bots root        L Open manager logs C Config/state paths")
        print("  Q Quit")
        choice = input("\nSelect: ").strip()
        if not choice:
            continue
        lower = choice.lower()
        if lower in {"q", "quit", "exit", "0"}:
            return
        if lower in {"r", "rescan"}:
            audited = scan_bots(cfg, save=True)
            pause(launcher_audit_text(cfg, audited))
        elif lower in {"w", "watch"}:
            watch_dashboard(cfg)
        elif lower in {"d", "diag", "diagnostics", "export"}:
            export_path = export_diagnostics(cfg)
            sidecar = export_path.with_name(export_path.name + ".sha256.txt")
            sidecar_note = str(sidecar) if sidecar.exists() else "unavailable; see manager log"
            pause(f"Diagnostic export created:\n{export_path}\nSHA256 metadata sidecar:\n{sidecar_note}")
        elif lower in {"p", "preflight", "selftest"}:
            pause(selftest_text(run_selftest(cfg, bots)))
        elif lower in {"o", "open"}:
            open_path(Path(str(cfg.get("bots_root", DEFAULT_BOTS_ROOT))))
        elif lower in {"l", "logs"}:
            open_path(logs_dir())
        elif lower in {"c", "config"}:
            pause(
                f"Config: {config_path()}\nRegistry: {registry_path()}\nRuntime: {runtime_state_path()}\n"
                f"Health learning: {health_state_path()}\nLatest status: {latest_status_path()}\n"
                f"Metrics: {metrics_path()}\nExports: {exports_dir()}"
            )
        else:
            bot = choose_bot_by_token(bots, choice)
            if bot:
                bot_menu(cfg, bot.name)
            else:
                pause("Unknown selection.")


def run_cli(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}")
    parser.add_argument("--root", help="Override bots root for this run; default C:\\Bots")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("menu", help="Open interactive menu")
    subparsers.add_parser("status", help="Print dashboard")
    subparsers.add_parser("dashboard", help="Print dashboard")
    subparsers.add_parser("scan", help="Rescan bot folders and audit launchers")
    subparsers.add_parser("audit", help="Rescan and print launcher safety audit")
    watch_parser = subparsers.add_parser("watch", help="Live dashboard until Ctrl+C")
    watch_parser.add_argument("--interval", type=int, default=None)
    subparsers.add_parser("selftest", help="Run preflight/self-test")
    subparsers.add_parser("export", help="Create safe diagnostic ZIP")
    subparsers.add_parser("open-root", help="Open bots root")
    subparsers.add_parser("open-logs", help="Open manager logs")
    subparsers.add_parser("config", help="Show state/config paths")

    start_parser = subparsers.add_parser("start", help="Start a bot by number/name/partial name")
    start_parser.add_argument("bot")
    start_parser.add_argument("--yes", action="store_true")
    start_parser.add_argument("--allow-duplicate", action="store_true", help="Override duplicate-instance protection")

    stop_parser = subparsers.add_parser("stop", help="Run configured stop script, or force-stop a managed tree")
    stop_parser.add_argument("bot")
    stop_parser.add_argument("--force", action="store_true")
    stop_parser.add_argument("--yes", action="store_true")

    adopt_parser = subparsers.add_parser("adopt", help="Adopt observed external process roots")
    adopt_parser.add_argument("bot")
    adopt_parser.add_argument("--yes", action="store_true")

    tail_parser = subparsers.add_parser("tail", help="Tail selected operational log")
    tail_parser.add_argument("bot")
    tail_parser.add_argument("--lines", type=int, default=80)

    args = parser.parse_args(argv)
    command = args.command or "menu"
    # Diagnostic export must be report-only. Load effective config without
    # persisting schema migrations so export cannot mutate config/state before
    # it produces the handoff ZIP. Other commands keep the normal migration path.
    cfg = load_config(
        root_override=args.root,
        persist_migrations=(command != "export"),
        recover_corrupt=(command != "export"),
    )
    if command != "export":
        cleanup_stale_temp_exports(cfg)
    try:
        if command == "menu":
            interactive_menu(cfg)
            return 0
        if command in {"status", "dashboard"}:
            print_dashboard(cfg, rescan=True)
            return 0
        if command == "scan":
            bots = scan_bots(cfg, save=True)
            print(f"Scanned {cfg.get('bots_root')}; found {len(bots)} folder(s).")
            return 0
        if command == "audit":
            bots = scan_bots(cfg, save=True)
            print(launcher_audit_text(cfg, bots))
            return 0
        if command == "watch":
            get_bots(cfg, rescan=True)
            watch_dashboard(cfg, interval=args.interval)
            return 0
        if command == "selftest":
            bots = get_bots(cfg, rescan=True)
            result = run_selftest(cfg, bots)
            print(selftest_text(result))
            return 1 if result["overall"] == "FAIL" else 0
        if command == "export":
            export_path = export_diagnostics(cfg)
            sidecar = export_path.with_name(export_path.name + ".sha256.txt")
            print(export_path)
            print(f"SHA256 metadata sidecar: {sidecar if sidecar.exists() else 'unavailable; see manager log'}")
            return 0
        if command == "open-root":
            open_path(Path(str(cfg.get("bots_root", DEFAULT_BOTS_ROOT))))
            return 0
        if command == "open-logs":
            open_path(logs_dir())
            return 0
        if command == "config":
            print(f"Effective root: {cfg.get('bots_root')}  (source: {cfg.get('_bots_root_source', 'unknown')})")
            print(f"Config:        {config_path()}")
            print(f"Registry:      {registry_path()}")
            print(f"Runtime state: {runtime_state_path()}")
            print(f"Health state:  {health_state_path()}")
            print(f"Latest status: {latest_status_path()}")
            print(f"Metrics:       {metrics_path()}")
            print(f"Logs:          {logs_dir()}")
            print(f"Exports:       {exports_dir()}")
            return 0
        if command in {"start", "stop", "adopt", "tail"}:
            bots = get_bots(cfg, rescan=True)
            bot = choose_bot_by_token(bots, getattr(args, "bot"))
            if not bot:
                print(f"Bot not found or partial name is ambiguous: {getattr(args, 'bot')}")
                print_dashboard(cfg, rescan=False)
                return 2
            if command == "start":
                return 0 if start_bot(bot, cfg, args.yes, args.allow_duplicate) else 1
            if command == "stop":
                return 0 if stop_bot(bot, cfg, args.force, args.yes) else 1
            if command == "adopt":
                return 0 if adopt_bot(bot, cfg, args.yes) else 1
            if command == "tail":
                tail_bot(bot, cfg, args.lines)
                return 0
        parser.print_help()
        return 2
    except KeyboardInterrupt:
        print("\nCanceled.")
        return 130
    except Exception as exc:
        log_event(f"Unhandled error: {exc}", "ERROR")
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(run_cli())
