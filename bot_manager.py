#!/usr/bin/env python3
"""Safety-first local monitor and controller for Windows automation folders.

The manager does not read child-project credentials, contact external services
on their behalf, or edit their source and configuration. Automatic launcher
detection blocks stop, setup, build, cleanup, and export scripts from being
selected as start commands. Force termination is deliberately disabled in the
public edition; reviewed project-scoped stop scripts remain explicit actions.

Copyright © 2026 Gateway Information Group LLC. All rights reserved.
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
import secrets
import shutil
import statistics
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unicodedata
import zipfile
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

def _sanitize_run_id(value: Any) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", str(value or "").strip()).strip("_-")
    return cleaned[:48]


APP_NAME = "BotOps Manager"
APP_VERSION = "1.13.0"
CONFIG_VERSION = 18
REGISTRY_VERSION = 2
RUNTIME_VERSION = 1
HEALTH_STATE_VERSION = 1
SECURITY_BOUNDARY_SCHEMA = "botops_security_boundary_v1"
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
DEFAULT_BOTS_ROOT = r"C:\Bots"
RUN_ID = _sanitize_run_id(os.environ.get("BOTOPS_RUN_ID")) or f"{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{os.getpid():x}"
JSON_INPUT_MAX_BYTES = 2_000_000
SUPPORT_MAX_ENTRY_BYTES_HARD = 4_000_000
SUPPORT_MAX_TOTAL_BYTES_HARD = 16_000_000
SUPPORT_LOG_TAIL_MAX_BYTES = 65_536
PROCESS_IDENTITY_TOLERANCE_SECONDS = 0.05

DEFAULT_CONFIG: Dict[str, Any] = {
    "version": CONFIG_VERSION,
    "bots_root": DEFAULT_BOTS_ROOT,
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
    "powershell_execution_policy_bypass": False,
    "export_refresh_registry": False,
    "support_max_files": 20,
    "support_max_entry_bytes": 1_000_000,
    "support_max_total_bytes": 5_000_000,
    "support_tmp_retention_hours": 24,
    "support_coverage_ledger_item_limit": 200,
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
        "support",
        "reports",
        "report",
        "support_export",
        "_BotOpsManager",
        "BotOps_Manager",
    ],
    "ignored_dir_patterns": [
        r"BotOps_Manager_v\d+\.\d+\.\d+",
        r"BotOps_Manager_v\d+\.\d+\.\d+_.+",
    ],
    "launcher_priority": [
        "start.bat",
        "run.bat",
        "launch.bat",
        "control_center.bat",
        "service_console.bat",
        "worker_console.bat",
        "bot.bat",
        "start.cmd",
        "run.cmd",
        "launch.cmd",
        "start.ps1",
        "run.ps1",
        "main.py",
        "bot.py",
        "worker.py",
        "service.py",
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
        "support",
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
        "task",
        "service",
        "bot",
        "daemon",
        "live",
        "production",
        "prod",
        "worker",
        "server",
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
        "cross_scope_action",
        "shared_resource",
        "global_shutdown",
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
        "task",
        "tasks",
        "job",
        "jobs",
        "result",
        "results",
        "progress",
        "queue",
        "queues",
        "status",
        "runtime",
        "connection",
        "error",
        "stdout",
        "stderr",
        "worker",
    ],
    "log_negative_terms": [
        "readme",
        "changelog",
        "manifest",
        "version",
        "license",
        "requirements",
        "export",
        "support",
        "paste",
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
        "support",
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
COMMAND_CENTER_LAUNCHER_NAMES = {"control_center.bat", "service_console.bat", "worker_console.bat"}
PROJECT_IDENTITY_START_TERMS = {"support"}
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
    "clock$",
    "conin$",
    "conout$",
    *{f"com{index}" for index in range(1, 10)},
    *{f"lpt{index}" for index in range(1, 10)},
    *{f"com{suffix}" for suffix in ("¹", "²", "³")},
    *{f"lpt{suffix}" for suffix in ("¹", "²", "³")},
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
SENSITIVE_SUPPORT_KEYS = {
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
    "account_id",
    "account_identifier",
    "account_number",
    "account_uuid",
    "client_id",
    "client_identifier",
    "customer_id",
    "organization_id",
    "organization_identifier",
    "portfolio_id",
    "profile_id",
    "subaccount_id",
    "sub_account_id",
    "tenant_id",
    "tenant_identifier",
    "user_id",
    "user_identifier",
}

_LOGGER: Optional[logging.Logger] = None
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


class ProcessInventory(list[ProcessInfo]):
    """Process records plus explicit enumeration-completeness provenance."""

    def __init__(
        self,
        values: Iterable[ProcessInfo] = (),
        *,
        complete: bool = False,
        source: str = "unknown",
    ) -> None:
        super().__init__(values)
        self.complete = bool(complete)
        self.source = str(source)

    def copy(self) -> "ProcessInventory":
        return ProcessInventory(self, complete=self.complete, source=self.source)


_PROCESS_CACHE: Tuple[float, ProcessInventory] = (0.0, ProcessInventory())


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


def path_is_reparse_or_symlink(path: Path) -> bool:
    """Return true for symbolic links, Windows junctions, and other reparse points."""
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    file_attributes = int(getattr(metadata, "st_file_attributes", 0))
    is_junction = getattr(path, "is_junction", None)
    try:
        junction = bool(is_junction()) if callable(is_junction) else False
    except OSError:
        junction = True
    return bool(path.is_symlink() or junction or (reparse_flag and file_attributes & reparse_flag))


def _managed_directory(name: str, *, create: bool) -> Path:
    root = app_root()
    if path_is_reparse_or_symlink(root) or not root.is_dir():
        raise RuntimeError("BotOps application root must be a real local directory, not a link or reparse point.")
    root_resolved = root.resolve(strict=True)
    path = root / name
    if path.exists() or path_is_reparse_or_symlink(path):
        if path_is_reparse_or_symlink(path) or not path.is_dir():
            raise RuntimeError(f"Managed directory is unsafe: {path}")
    elif create:
        path.mkdir(parents=False, exist_ok=False)
    else:
        return path
    if path_is_reparse_or_symlink(path):
        raise RuntimeError(f"Managed directory became a link or reparse point: {path}")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise RuntimeError(f"Managed directory escaped the BotOps application root: {path}") from exc
    return resolved


def state_dir() -> Path:
    return _managed_directory("state", create=not manager_state_is_read_only())


def logs_dir() -> Path:
    return _managed_directory("logs", create=not manager_state_is_read_only())


def exports_dir() -> Path:
    return _managed_directory("exports", create=True)


def config_path(*, create_parent: bool = True) -> Path:
    return _managed_directory("state", create=create_parent and not manager_state_is_read_only()) / "bot_manager_config.json"


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


def local_now() -> dt.datetime:
    """Return the operating system's configured local time."""
    return dt.datetime.now().astimezone()


def local_stamp_for_filename() -> str:
    # Include milliseconds and the operating system's timezone label so quick
    # support exports do not collide and filenames remain Windows-safe.
    now = local_now()
    zone = re.sub(r"[^A-Za-z0-9]+", "", now.tzname() or "LOCAL") or "LOCAL"
    return now.strftime("%Y%m%d_%H%M%S_") + f"{now.microsecond // 1000:03d}_{zone}"


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
    if manager_state_is_read_only():
        return
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


def _stat_is_reparse(metadata: os.stat_result) -> bool:
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    file_attributes = int(getattr(metadata, "st_file_attributes", 0))
    return bool(reparse_flag and file_attributes & reparse_flag)


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    try:
        return bool(os.path.samestat(first, second))
    except (AttributeError, OSError, ValueError):
        return (int(first.st_dev), int(first.st_ino)) == (int(second.st_dev), int(second.st_ino))


def read_bounded_regular_bytes(path: Path, max_bytes: int) -> bytes:
    """Read one regular non-link file through a single verified descriptor."""
    byte_limit = int(max_bytes)
    if byte_limit < 0:
        raise ValueError("File byte limit must be non-negative")
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or _stat_is_reparse(before):
        raise ValueError("linked, reparse-point, or non-regular files are not accepted")

    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(str(path), flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _stat_is_reparse(opened)
            or not _same_file_identity(before, opened)
        ):
            raise ValueError("File identity changed or resolved through a link/reparse point")
        if opened.st_size > byte_limit:
            raise ValueError(f"File exceeds {byte_limit} byte limit")

        chunks: List[bytes] = []
        remaining = byte_limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > byte_limit:
            raise ValueError(f"File exceeds {byte_limit} byte limit")
        return payload
    finally:
        os.close(descriptor)


def read_bounded_json(path: Path, max_bytes: int) -> Any:
    payload = read_bounded_regular_bytes(path, max_bytes)
    return json.loads(payload.decode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
    """Prevent support/report paths from repairing or writing manager state."""
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
    """Small cross-process lock for state writes; ambiguous stale locks fail closed."""
    lock_path = state_dir() / ".write.lock"
    deadline = time.monotonic() + max(0.1, timeout_seconds)
    acquired = False
    lock_id = secrets.token_hex(16)
    while time.monotonic() < deadline:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            payload = json.dumps({"pid": os.getpid(), "created_at": time.time(), "lock_id": lock_id})
            os.write(fd, payload.encode("utf-8"))
            os.close(fd)
            acquired = True
            break
        except FileExistsError:
            time.sleep(0.05)
    if not acquired:
        raise TimeoutError(f"Timed out waiting for state lock: {lock_path}")
    try:
        yield
    finally:
        try:
            current = read_bounded_json(lock_path, JSON_INPUT_MAX_BYTES)
            if isinstance(current, dict) and current.get("lock_id") == lock_id:
                lock_path.unlink(missing_ok=True)
        except Exception:
            pass


def control_action_lock_path() -> Path:
    return state_dir() / ".control_action.lock"


def read_control_action_lock() -> Dict[str, Any]:
    path = control_action_lock_path()
    try:
        raw = read_bounded_json(path, JSON_INPUT_MAX_BYTES)
        if not isinstance(raw, dict):
            raw = {}
    except FileNotFoundError:
        return {"active": False}
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
    """Serialize start, stop-script, and adoption control actions.

    Multiple BotOps windows may safely monitor at the same time, but mutable
    control actions must not race. The lock is deliberately file-local and
    transparent so it works without elevation and shows up in support.
    """
    lock_path = control_action_lock_path()
    timeout_seconds = max(1.0, float(cfg.get("control_action_lock_timeout_seconds", 20)))
    deadline = time.monotonic() + timeout_seconds
    payload = {
        "pid": os.getpid(),
        "lock_id": secrets.token_hex(16),
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
            time.sleep(0.1)
    if not acquired:
        owner_desc = f"action={last_owner.get('action', '?')} bot={last_owner.get('bot_name', '?')} pid={last_owner.get('pid', '?')}"
        raise TimeoutError(f"Another BotOps control action is active ({owner_desc}). Try again after it completes.")
    try:
        yield
    finally:
        try:
            current = read_bounded_json(lock_path, JSON_INPUT_MAX_BYTES)
            if isinstance(current, dict) and current.get("lock_id") == payload["lock_id"]:
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
    try:
        return read_bounded_json(path, JSON_INPUT_MAX_BYTES)
    except FileNotFoundError:
        return default
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
    try:
        return read_bounded_json(path, JSON_INPUT_MAX_BYTES)
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
        "start_settle_seconds",
        "stop_wait_seconds",
        "control_action_lock_timeout_seconds",
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
        "support_max_files",
        "support_max_entry_bytes",
        "support_max_total_bytes",
        "support_tmp_retention_hours",
        "support_coverage_ledger_item_limit",
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
                "watch_interval_seconds",
                "watch_rescan_seconds",
                "adaptive_health_min_samples",
                "health_stale_confirmations",
                "health_future_skew_seconds",
                "health_contract_max_bytes",
                "support_max_files",
                "support_max_entry_bytes",
                "support_max_total_bytes",
                "support_tmp_retention_hours",
                "support_coverage_ledger_item_limit",
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

    # Stop launchers are scoped control operations. Older configs included
    # "exit" as a stop term; remove it so broad exit helpers cannot become
    # automatic stop handlers.
    cfg["stop_terms"] = [term for term in cfg.get("stop_terms", []) if str(term).strip().lower() != "exit"]

    bool_keys = [
        "scan_immediate_child_folders_only",
        "scan_nested_collections",
        "confirm_start_stop",
        "control_managed_processes_only",
        "powershell_execution_policy_bypass",
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
    cfg["control_action_lock_timeout_seconds"] = max(1, min(120, int(cfg.get("control_action_lock_timeout_seconds", 20))))
    cfg["adaptive_health_min_samples"] = max(3, min(20, int(cfg.get("adaptive_health_min_samples", 5))))
    cfg["adaptive_health_max_threshold_factor"] = max(
        1.0, min(24.0, float(cfg.get("adaptive_health_max_threshold_factor", 6.0)))
    )
    cfg["health_stale_confirmations"] = max(1, min(5, int(cfg.get("health_stale_confirmations", 2))))
    cfg["health_hard_stale_factor"] = max(1.0, min(10.0, float(cfg.get("health_hard_stale_factor", 2.0))))
    cfg["health_future_skew_seconds"] = max(0, min(3600, int(cfg.get("health_future_skew_seconds", 120))))
    cfg["health_contract_max_bytes"] = max(1024, min(1024 * 1024, int(cfg.get("health_contract_max_bytes", 65536))))
    cfg["support_max_files"] = max(12, min(20, int(cfg.get("support_max_files", 20))))
    cfg["support_max_entry_bytes"] = max(
        65_536,
        min(SUPPORT_MAX_ENTRY_BYTES_HARD, int(cfg.get("support_max_entry_bytes", 1_000_000))),
    )
    cfg["support_max_total_bytes"] = max(
        int(cfg["support_max_entry_bytes"]),
        min(SUPPORT_MAX_TOTAL_BYTES_HARD, int(cfg.get("support_max_total_bytes", 5_000_000))),
    )
    cfg["support_tmp_retention_hours"] = max(1, min(168, int(cfg.get("support_tmp_retention_hours", 24))))
    cfg["support_coverage_ledger_item_limit"] = max(20, min(500, int(cfg.get("support_coverage_ledger_item_limit", 200))))

    root = cfg.get("bots_root", DEFAULT_BOTS_ROOT)
    cfg["bots_root"] = str(root).strip() or DEFAULT_BOTS_ROOT
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
    path = config_path(create_parent=bool(persist_migrations or recover_corrupt))
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


def directory_is_safe_within(path: Path, root: Path) -> bool:
    try:
        if path_is_reparse_or_symlink(root) or path_is_reparse_or_symlink(path):
            return False
        if not root.is_dir() or not path.is_dir():
            return False
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def configured_ignored_dir_name(path: Path, cfg: Dict[str, Any]) -> bool:
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
    return False


def is_ignored_dir(path: Path, cfg: Dict[str, Any], manager_root: Optional[Path] = None) -> bool:
    if path_is_reparse_or_symlink(path):
        return True
    if configured_ignored_dir_name(path, cfg):
        return True
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


def _record_discovery_error(scan_errors: Optional[List[str]], message: str) -> None:
    log_event(message, "WARNING")
    if scan_errors is not None:
        scan_errors.append(message)


def _safe_scan_subdirectories(
    current_path: Path,
    names: Sequence[str],
    scan_root: Path,
    cfg: Dict[str, Any],
    manager_root: Optional[Path],
    scan_errors: Optional[List[str]],
) -> List[str]:
    """Keep intentional real subdirectories and surface every ambiguous skip."""
    selected: List[str] = []
    for name in names:
        child = current_path / name
        if configured_ignored_dir_name(child, cfg):
            continue
        try:
            metadata = os.lstat(child)
        except OSError as exc:
            _record_discovery_error(scan_errors, f"Could not inspect directory candidate {child}: {exc}")
            continue
        if _stat_is_reparse(metadata) or path_is_reparse_or_symlink(child):
            _record_discovery_error(scan_errors, f"Linked or reparse-point directory candidate was not scanned: {child}")
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        if manager_root is not None:
            try:
                if child.resolve(strict=True) == manager_root.resolve(strict=True):
                    continue
            except (OSError, RuntimeError) as exc:
                _record_discovery_error(scan_errors, f"Could not resolve directory candidate {child}: {exc}")
                continue
        if not directory_is_safe_within(child, scan_root):
            _record_discovery_error(scan_errors, f"Directory candidate failed containment or safety validation: {child}")
            continue
        selected.append(name)
    return selected


def candidate_launcher_files(
    folder: Path,
    cfg: Dict[str, Any],
    scan_errors: Optional[List[str]] = None,
) -> List[Path]:
    max_depth = int(cfg.get("launcher_search_depth", 2))
    max_candidates = int(cfg.get("max_launcher_candidates_per_bot", 300))
    manager_root = app_root()
    found: Dict[str, Path] = {}
    if not directory_is_safe_within(folder, folder):
        if scan_errors is not None:
            _record_discovery_error(scan_errors, f"Launcher root failed containment or safety validation: {folder}")
        return []
    def walk_error(exc: OSError) -> None:
        _record_discovery_error(scan_errors, f"Could not traverse launcher files under {folder}: {exc}")

    try:
        for current, dirs, files in os.walk(folder, onerror=walk_error):
            current_path = Path(current)
            dirs[:] = _safe_scan_subdirectories(
                current_path, dirs, folder, cfg, manager_root, scan_errors
            )
            depth = path_depth_relative(folder, current_path)
            if depth > max_depth:
                dirs[:] = []
                continue
            for filename in files:
                path = current_path / filename
                if path.suffix.lower() not in SUPPORTED_LAUNCH_SUFFIXES and filename.lower() != "package.json":
                    continue
                try:
                    metadata = os.lstat(path)
                except OSError as exc:
                    _record_discovery_error(scan_errors, f"Could not inspect launcher candidate {path}: {exc}")
                    continue
                if (
                    _stat_is_reparse(metadata)
                    or path_is_reparse_or_symlink(path)
                    or not stat.S_ISREG(metadata.st_mode)
                    or not is_path_within(path, folder)
                ):
                    _record_discovery_error(scan_errors, f"Launcher candidate failed regular-file or containment validation: {path}")
                    continue
                found[str(path).lower()] = path
                if len(found) >= max_candidates:
                    _record_discovery_error(
                        scan_errors,
                        f"Launcher candidate limit reached under {folder}; discovery was intentionally incomplete at {max_candidates} file(s).",
                    )
                    return list(found.values())
    except Exception as exc:
        _record_discovery_error(scan_errors, f"Could not traverse launcher files under {folder}: {exc}")
    return list(found.values())


def package_has_start_script(path: Path) -> bool:
    try:
        raw = read_bounded_json(path, JSON_INPUT_MAX_BYTES)
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
        "support",
        "backup",
        "restore",
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


def audit_launcher_candidates(
    folder: Path,
    cfg: Dict[str, Any],
    scan_errors: Optional[List[str]] = None,
) -> Tuple[List[LauncherCandidate], List[LauncherCandidate]]:
    files = candidate_launcher_files(folder, cfg, scan_errors)
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


def folder_looks_like_bot(folder: Path, cfg: Dict[str, Any], scan_errors: Optional[List[str]] = None) -> bool:
    if not directory_is_safe_within(folder, folder):
        if scan_errors is not None:
            _record_discovery_error(scan_errors, f"Project folder failed containment or safety validation: {folder}")
        return False
    starts, stops = audit_launcher_candidates(folder, cfg, scan_errors)
    if starts or stops:
        return True
    indicators = {"requirements.txt", "pyproject.toml", "package.json", "dockerfile", "docker-compose.yml", "compose.yml"}
    try:
        for item in folder.iterdir():
            if item.is_file() and item.name.lower() in indicators:
                return True
    except Exception as exc:
        _record_discovery_error(scan_errors, f"Could not inspect project indicators under {folder}: {exc}")
        return False
    return False


def root_safe_start(
    folder: Path,
    cfg: Dict[str, Any],
    scan_errors: Optional[List[str]] = None,
) -> Optional[LauncherCandidate]:
    """Return a safe start candidate located at the project root only."""
    minimum = int(cfg.get("min_start_score", 60))
    starts, _ = audit_launcher_candidates(folder, cfg, scan_errors)
    return next(
        (item for item in starts if not item.blocked and item.score >= minimum and path_depth_relative(folder, Path(item.path).parent) == 0),
        None,
    )


def root_safe_stop(
    folder: Path,
    cfg: Dict[str, Any],
    scan_errors: Optional[List[str]] = None,
) -> Optional[LauncherCandidate]:
    minimum = int(cfg.get("min_stop_score", 50))
    _, stops = audit_launcher_candidates(folder, cfg, scan_errors)
    return next(
        (item for item in stops if not item.blocked and item.score >= minimum and path_depth_relative(folder, Path(item.path).parent) == 0),
        None,
    )


def folder_has_project_root_evidence(
    folder: Path,
    cfg: Dict[str, Any],
    scan_errors: Optional[List[str]] = None,
) -> bool:
    if not directory_is_safe_within(folder, folder):
        if scan_errors is not None:
            _record_discovery_error(scan_errors, f"Project-root folder failed containment or safety validation: {folder}")
        return False
    if root_safe_start(folder, cfg, scan_errors) or root_safe_stop(folder, cfg, scan_errors):
        return True
    indicators = {"requirements.txt", "pyproject.toml", "package.json", "dockerfile", "docker-compose.yml", "compose.yml"}
    try:
        for item in folder.iterdir():
            if item.is_file() and item.name.lower() in indicators:
                return True
    except Exception as exc:
        _record_discovery_error(scan_errors, f"Could not inspect project-root evidence under {folder}: {exc}")
        return False
    return False


def nested_bot_folders(
    container: Path,
    cfg: Dict[str, Any],
    scan_errors: Optional[List[str]] = None,
) -> List[Path]:
    """Discover nested runnable project roots inside a collection folder.

    This keeps folders such as C:\\Bots\\Workers from becoming one mixed
    control surface when each child worker has its own launcher/stop files.
    """
    manager_root = app_root()
    max_depth = int(cfg.get("nested_collection_depth", 3))
    found: List[Path] = []
    if not directory_is_safe_within(container, container):
        if scan_errors is not None:
            _record_discovery_error(scan_errors, f"Nested collection failed containment or safety validation: {container}")
        return found
    def walk_error(exc: OSError) -> None:
        _record_discovery_error(scan_errors, f"Could not scan nested bot folders under {container}: {exc}")

    try:
        for current, dirs, _files in os.walk(container, onerror=walk_error):
            current_path = Path(current)
            dirs[:] = _safe_scan_subdirectories(
                current_path, dirs, container, cfg, manager_root, scan_errors
            )
            depth = path_depth_relative(container, current_path)
            if depth <= 0:
                continue
            if depth > max_depth:
                dirs[:] = []
                continue
            if folder_has_project_root_evidence(current_path, cfg, scan_errors):
                found.append(current_path)
                dirs[:] = []
    except Exception as exc:
        _record_discovery_error(scan_errors, f"Could not scan nested bot folders under {container}: {exc}")
    return found


def candidate_bot_folders(
    root: Path,
    cfg: Dict[str, Any],
    scan_errors: Optional[List[str]] = None,
) -> List[Path]:
    if not directory_is_safe_within(root, root):
        message = f"Bot root is not a safe real directory and was not scanned: {root}"
        if scan_errors is not None:
            _record_discovery_error(scan_errors, message)
        elif root.exists() or path_is_reparse_or_symlink(root):
            log_event(message, "WARNING")
        return []
    manager_root = app_root()
    candidates: Dict[str, Path] = {}

    def add(path: Path) -> None:
        if not directory_is_safe_within(path, root):
            _record_discovery_error(scan_errors, f"Discovered bot folder failed containment or safety revalidation: {path}")
            return
        try:
            key = str(path.resolve()).lower()
        except Exception:
            key = str(path).lower()
        candidates[key] = path

    if cfg.get("scan_immediate_child_folders_only", True):
        try:
            root_items = sorted(root.iterdir(), key=lambda path: path.name.lower())
            child_names = _safe_scan_subdirectories(
                root, [item.name for item in root_items], root, cfg, manager_root, scan_errors
            )
            for child_name in child_names:
                child = root / child_name
                child_has_root = folder_has_project_root_evidence(child, cfg, scan_errors)
                nested = nested_bot_folders(child, cfg, scan_errors) if cfg.get("scan_nested_collections", True) else []
                if child_has_root:
                    add(child)
                elif nested:
                    for nested_child in nested:
                        add(nested_child)
                elif folder_looks_like_bot(child, cfg, scan_errors):
                    # Monitor-only fallback: keep odd legacy projects visible, but
                    # without pretending nested launchers are safe for the parent.
                    add(child)
        except Exception as exc:
            _record_discovery_error(scan_errors, f"Could not enumerate bot folders under {root}: {exc}")
    else:
        max_depth = int(cfg.get("nested_collection_depth", 3))
        def walk_error(exc: OSError) -> None:
            _record_discovery_error(scan_errors, f"Could not enumerate bot folders under {root}: {exc}")

        try:
            for current, dirs, _files in os.walk(root, onerror=walk_error):
                current_path = Path(current)
                dirs[:] = _safe_scan_subdirectories(
                    current_path, dirs, root, cfg, manager_root, scan_errors
                )
                if current_path == root:
                    continue
                if path_depth_relative(root, current_path) > max_depth:
                    dirs[:] = []
                    continue
                if folder_has_project_root_evidence(current_path, cfg, scan_errors):
                    add(current_path)
                    dirs[:] = []
        except Exception as exc:
            _record_discovery_error(scan_errors, f"Could not enumerate bot folders under {root}: {exc}")
    return sorted(candidates.values(), key=lambda path: str(path).lower())


def classify_bot(folder: Path, launcher_paths: Iterable[str]) -> str:
    text = " ".join([folder.name, *[Path(path).name for path in launcher_paths if path]]).lower()
    compact_text = compact_name(text)
    service_terms = {
        "service",
        "server",
        "daemon",
        "listener",
        "scheduler",
        "policy_service",
        "data_service",
        "api",
        "web",
    }
    worker_terms = {"worker", "processing", "native_worker", "throughput"}
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
        "inspector",
        "network",
        "support",
        "tool",
        "utility",
    }
    if any(term in text or term in compact_text for term in manager_terms):
        return "manager"
    if any(term in text for term in service_terms):
        return "service"
    if any(term in text for term in worker_terms):
        return "worker"
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
    preserved = {
        name: bot_record_from_dict(name, data)
        for name, data in sorted(existing.items())
        if isinstance(data, dict)
    }
    if not root.exists() and not path_is_reparse_or_symlink(root):
        log_event(f"Bots root does not exist; registry was not rewritten: {root}", "WARNING")
        return preserved
    if not directory_is_safe_within(root, root):
        log_event(f"Bots root is not a safe real directory; registry and runtime state were not rewritten: {root}", "WARNING")
        return preserved
    found: Dict[str, BotRecord] = {}
    changes: List[str] = []
    scan_errors: List[str] = []
    candidates = candidate_bot_folders(root, cfg, scan_errors)
    if scan_errors:
        log_event(
            f"Bot discovery was incomplete; registry and runtime state were not rewritten ({len(scan_errors)} traversal error(s)).",
            "WARNING",
        )
        return preserved

    for folder in candidates:
        name = relative_bot_name(root, folder)
        old = existing.get(name, {}) if isinstance(existing.get(name), dict) else {}
        starts, stops = audit_launcher_candidates(folder, cfg, scan_errors)
        if scan_errors:
            log_event(
                f"Launcher discovery was incomplete; registry and runtime state were not rewritten ({len(scan_errors)} traversal error(s)).",
                "WARNING",
            )
            return preserved
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


def get_windows_processes() -> ProcessInventory:
    ps_command = (
        "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        "$cimItems = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop); "
        "$items = @($cimItems | ForEach-Object { "
        "$created = $null; if ($_.CreationDate) { $created = $_.CreationDate.ToUniversalTime().ToString('o') }; "
        "[PSCustomObject]@{ ProcessId=$_.ProcessId; ParentProcessId=$_.ParentProcessId; Name=$_.Name; "
        "ExecutablePath=$_.ExecutablePath; CommandLine=$_.CommandLine; CreationDate=$created; WorkingSetSize=$_.WorkingSetSize } }); "
        "[PSCustomObject]@{ Complete=$true; ReportedCount=$cimItems.Count; Items=@($items) } | ConvertTo-Json -Compress -Depth 4"
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
            if not isinstance(raw, dict) or raw.get("Complete") is not True:
                continue
            raw_items_value = raw.get("Items", [])
            raw_items = (
                raw_items_value
                if isinstance(raw_items_value, list)
                else [raw_items_value]
                if isinstance(raw_items_value, dict)
                else []
            )
            try:
                reported_count = int(raw.get("ReportedCount"))
            except Exception:
                reported_count = -1
            processes: List[ProcessInfo] = []
            records_complete = True
            for item in raw_items:
                if not isinstance(item, dict):
                    records_complete = False
                    continue
                try:
                    raw_pid = item.get("ProcessId")
                    pid = int(raw_pid) if raw_pid is not None else -1
                except Exception:
                    pid = -1
                if pid < 0:
                    records_complete = False
                    continue
                if pid == 0:
                    # Win32_Process includes the System Idle Process. It proves
                    # enumeration breadth but is never a controllable process.
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
            complete = records_complete and reported_count >= 0 and reported_count == len(raw_items)
            return ProcessInventory(processes, complete=complete, source=f"{executable}:Win32_Process")
        except Exception as exc:
            log_event(f"Process scan through {executable} failed: {exc}", "WARNING")
    log_event("No usable PowerShell process scan was available; process status may be incomplete.", "WARNING")
    return ProcessInventory(source="windows-cim-unavailable")


def get_posix_processes() -> ProcessInventory:
    try:
        completed = subprocess.run(
            ["ps", "-eo", "pid=,ppid=,comm=,args="],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        processes: List[ProcessInfo] = []
        complete = completed.returncode == 0
        for line in completed.stdout.splitlines():
            parts = line.strip().split(None, 3)
            if len(parts) < 3:
                complete = False
                continue
            processes.append(
                ProcessInfo(
                    pid=int(parts[0]),
                    parent_pid=int(parts[1]),
                    name=parts[2],
                    command_line=parts[3] if len(parts) > 3 else "",
                )
            )
        return ProcessInventory(processes, complete=complete, source="ps")
    except Exception:
        return ProcessInventory(source="ps-unavailable")


def get_processes(cfg: Optional[Dict[str, Any]] = None, *, force: bool = False) -> ProcessInventory:
    global _PROCESS_CACHE
    cache_seconds = float((cfg or DEFAULT_CONFIG).get("process_cache_seconds", 2))
    now = time.monotonic()
    if not force and _PROCESS_CACHE[1] and now - _PROCESS_CACHE[0] <= cache_seconds:
        return _PROCESS_CACHE[1].copy()
    processes = get_windows_processes() if is_windows_host() else get_posix_processes()
    _PROCESS_CACHE = (now, processes.copy())
    return processes.copy()


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
    if not isinstance(processes, ProcessInventory) or not processes.complete:
        return False
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
        if abs(expected_created - process.creation_time) > PROCESS_IDENTITY_TOLERANCE_SECONDS:
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
    # Multi-worker and multi-stream services commonly expose one *_latest.log per
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
    and never causes an automatic start, stop, restart, adoption, or forced termination.
    File mtime remains the freshness clock; the embedded timestamp is checked for
    consistency and clock skew rather than trusted as a control authority.
    """
    now_value = time.time() if now is None else float(now)
    reasons = ["structured BotOps health contract"]
    errors: List[str] = []
    linked_contract = path_is_reparse_or_symlink(path)
    stat = None if linked_contract else safe_stat(path)
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

    if linked_contract:
        errors.append("contract links and reparse points are not trusted")
        return result()
    if stat is None:
        errors.append("contract could not be stat-ed")
        return result()
    if not is_path_within(path, bot_path):
        errors.append("contract is outside the bot folder")
        return result()
    maximum = max(1024, min(1024 * 1024, int(cfg.get("health_contract_max_bytes", 65536))))
    if stat.st_size > maximum:
        errors.append(f"contract exceeds {maximum} byte limit")
        return result()
    try:
        payload = read_bounded_json(path, maximum)
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
    if expected_started is None or process.creation_time is None:
        return False
    return abs(float(expected_started) - float(process.creation_time)) <= PROCESS_IDENTITY_TOLERANCE_SECONDS


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

    This is support evidence, not an automatic restart trigger. File mtimes
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
            warnings.append("external process; monitor-only unless explicitly adopted")
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
        # is useful in support but never triggers a restart or stop action.
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
    root_raw = str(root_text).strip().strip('"')
    child_raw = str(child_text).strip().strip('"')
    root_windows = ntpath.isabs(root_raw)
    child_windows = ntpath.isabs(child_raw)
    if root_windows or child_windows:
        if not (root_windows and child_windows):
            return False
        root_norm = ntpath.normcase(ntpath.normpath(root_raw.replace("/", "\\")))
        child_norm = ntpath.normcase(ntpath.normpath(child_raw.replace("/", "\\")))
        try:
            return ntpath.commonpath([root_norm, child_norm]) == root_norm
        except ValueError:
            return False
    try:
        root_path = Path(root_raw).expanduser().resolve(strict=False)
        child_path = Path(child_raw).expanduser().resolve(strict=False)
        child_path.relative_to(root_path)
        return True
    except (OSError, RuntimeError, ValueError):
        return False


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
        f"{APP_NAME} v{APP_VERSION} | root: {root} | force termination: disabled in public edition",
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
    lines.append("Tracking: MANAGED = started/adopted and identity-verified; OBSERVED = monitor-only. Force termination is disabled.")
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


def revalidate_control_launcher(
    bot: BotRecord,
    cfg: Dict[str, Any],
    role: str,
) -> Optional[LauncherCandidate]:
    """Re-audit a persisted launcher immediately before a control action."""
    root = Path(str(cfg.get("bots_root", DEFAULT_BOTS_ROOT))).expanduser()
    folder = Path(bot.path)
    if not directory_is_safe_within(root, root) or not directory_is_safe_within(folder, root):
        return None
    configured = Path(bot.launcher if role == "start" else bot.stop_launcher)
    if (
        not configured.is_file()
        or path_is_reparse_or_symlink(configured)
        or not is_path_within(configured, folder)
    ):
        return None
    starts, stops = audit_launcher_candidates(folder, cfg)
    candidates = starts if role == "start" else stops
    configured_resolved = configured.resolve(strict=True)
    selected = next(
        (
            candidate
            for candidate in candidates
            if Path(candidate.path).resolve(strict=True) == configured_resolved
        ),
        None,
    )
    if selected is None or selected.blocked:
        return None
    minimum = int(cfg.get("min_start_score" if role == "start" else "min_stop_score", 60 if role == "start" else 50))
    persisted_kind = bot.launcher_kind if role == "start" else bot.stop_launcher_kind
    if selected.score < minimum or selected.kind != persisted_kind or launcher_kind(configured) != selected.kind:
        return None
    return selected


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
        print(f"Start blocked: {bot.name} already has a {mode} process set. This prevents accidental duplicate instances.")
        if tracking.observed_processes:
            print("Use Adopt in the bot menu after reviewing the observed roots.")
        return False

    if not confirm_action(
        f"Start {bot.name} with {launcher.name}? Its own code may contact external services and act under its current configuration.",
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
                print(f"Start blocked: {bot.name} already has a {mode} process set. This prevents accidental duplicate instances.")
                if tracking.observed_processes:
                    print("Use Adopt in the bot menu after reviewing the observed roots.")
                return False
            current_launcher = revalidate_control_launcher(bot, cfg, "start")
            if current_launcher is None:
                print("Start blocked: the persisted launcher no longer passes the current containment, type, and role audit.")
                return False
            bot_path = Path(bot.path).resolve(strict=True)
            launcher = Path(current_launcher.path).resolve(strict=True)
            runner = build_runner_command_path(launcher, current_launcher.kind, bot_path, cfg)
            title = sanitize_title(f"BotOps - {bot.name}")
            command = f"title {title} & cd /d {cmd_quote(str(bot_path))} & {runner}"
            started_at = time.time()
            process = popen_new_console(command, bot_path, keep_open=True, env=child_environment(bot, "start"))
            immediate = get_processes(cfg, force=True)
            immediate_root = next((item for item in immediate if item.pid == process.pid), None)
            immediate_created = (
                immediate_root.creation_time
                if process_inventory_reliable(immediate)
                and immediate_root is not None
                and immediate_root.creation_time is not None
                and process.poll() is None
                else None
            )
            settle = max(0.0, float(cfg.get("start_settle_seconds", 1.5)))
            if settle:
                time.sleep(settle)
            refreshed = get_processes(cfg, force=True)
            by_pid = {item.pid: item for item in refreshed}
            root = by_pid.get(process.pid)
            identity_verified = bool(
                process_inventory_reliable(refreshed)
                and immediate_created is not None
                and root is not None
                and root.creation_time is not None
                and process.poll() is None
                and abs(root.creation_time - immediate_created) <= PROCESS_IDENTITY_TOLERANCE_SECONDS
            )
            if identity_verified and root is not None:
                record_runtime_roots(bot, [root], started_at)
                log_event(f"Start requested for {bot.name}; launcher={launcher}; verified_root_pid={root.pid}")
                print(f"Start requested: {bot.name} (identity-verified root PID: {root.pid})")
            else:
                log_event(f"Start requested for {bot.name}; launcher={launcher}; ownership_not_recorded", "WARNING")
                print(
                    f"Start requested: {bot.name}. The exact launched PID and creation identity could not be verified, "
                    "so BotOps recorded no control ownership and will treat the process as monitor-only."
                )
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
        print(f"No stop script is configured for {bot.name}. Use Profile to select a reviewed project-scoped stop script.")
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
        f"Run stop script {stop_path.name} for {bot.name}? Review the file name carefully; emergency-stop scripts can affect shared resources or other work.",
        cfg,
        assume_yes,
    ):
        print("Stop canceled.")
        return False
    try:
        with control_action_lock(bot.name, "stop-script", cfg):
            current_stop = revalidate_control_launcher(bot, cfg, "stop")
            if current_stop is None or not stop_scope_matches_start(Path(bot.path), bot.launcher, current_stop.path):
                print("Stop blocked: the persisted stop script no longer passes the current containment, type, role, and scope audit.")
                return False
            bot_path = Path(bot.path).resolve(strict=True)
            stop_path = Path(current_stop.path).resolve(strict=True)
            runner = build_runner_command_path(stop_path, current_stop.kind, bot_path, cfg)
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
        f"TRACKING OWNERSHIP CHANGE: adopt observed {tracking.observed_confidence.lower()}-confidence root process(es) for {bot.name}: {details}. Evidence: {reason_text or 'path match'}. This records identity-bound monitoring state; force termination remains disabled.",
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
    del bot, cfg, assume_yes
    print(
        "Force termination is deliberately disabled in the public portfolio edition. "
        "Use a reviewed, project-scoped stop script or stop the process through Windows directly."
    )
    return False


def stop_bot(bot: BotRecord, cfg: Dict[str, Any], assume_yes: bool = False) -> bool:
    return run_stop_script(bot, cfg, assume_yes)


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


def tail_file(path: Path, lines: int = 80, max_bytes: int = SUPPORT_LOG_TAIL_MAX_BYTES) -> str:
    try:
        metadata = os.lstat(path)
        if path_is_reparse_or_symlink(path) or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("linked, reparse-point, or non-regular files are not accepted")
        byte_limit = max(1_024, min(SUPPORT_MAX_ENTRY_BYTES_HARD, int(max_bytes)))
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            end = stream.tell()
            position = max(0, end - byte_limit)
            stream.seek(position)
            data = stream.read(byte_limit)
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
            categories = ["service", "worker", "utility", "manager", "unknown"]
            print("1 service 2 worker   3 utility   4 unknown   A automatic")
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
        print("  S Start                 X Run stop script")
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
    if bot.category in {"service", "worker"}:
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
        # Support export must not create even a temporary state probe. This
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
    current_config_path = config_path()
    if current_config_path.exists():
        try:
            read_bounded_json(current_config_path, JSON_INPUT_MAX_BYTES)
            add("Config JSON", "PASS", str(current_config_path))
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
        f"active action={control_lock.get('action', '?')} bot={control_lock.get('bot_name', '?')} age_seconds={control_lock.get('age_seconds', '?')}" if control_lock.get("active") else "no active start/stop/adopt lock",
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
    security_boundary = build_security_boundary(cfg)
    add(
        "Runtime security boundary",
        "PASS",
        "no security-setting changes, exclusions, persistence installation, runtime download-and-execute, or execution-policy bypass",
    )

    overall = "FAIL" if any(item["status"] == "FAIL" for item in checks) else "WARN" if any(item["status"] == "WARN" for item in checks) else "PASS"
    result = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "created_at": utc_stamp(),
        "overall": overall,
        "security_boundary": security_boundary,
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
            raw = read_bounded_json(lock_path, JSON_INPUT_MAX_BYTES)
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


def sensitive_support_key(key: Any) -> bool:
    key_text = str(key).strip()
    # Split both ordinary camelCase and acronym boundaries before applying the
    # same separator-insensitive matching used for JSON/config keys.
    key_text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key_text)
    key_text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", key_text)
    normalized = re.sub(r"[^a-z0-9]+", "_", key_text.lower()).strip("_")
    if normalized in SENSITIVE_SUPPORT_KEYS:
        return True
    return any(normalized.endswith("_" + item) for item in SENSITIVE_SUPPORT_KEYS)


def sanitize_for_support(value: Any, cfg: Dict[str, Any]) -> Any:
    if isinstance(value, dict):
        sanitized: Dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if sensitive_support_key(key_text):
                if item is None:
                    sanitized[key_text] = None
                elif item == "" or item == b"":
                    sanitized[key_text] = ""
                elif isinstance(item, bool):
                    sanitized[key_text] = item
                else:
                    sanitized[key_text] = "***REDACTED_PRESENT***"
            else:
                sanitized[key_text] = sanitize_for_support(item, cfg)
        return sanitized
    if isinstance(value, list):
        return [sanitize_for_support(item, cfg) for item in value]
    if isinstance(value, tuple):
        return [sanitize_for_support(item, cfg) for item in value]
    if isinstance(value, str):
        return relative_sanitized_path(value, cfg)
    return value


def build_environment_snapshot(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Return a compact, redacted runtime snapshot for support."""
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
        "timezone_local": local_now().isoformat(timespec="seconds"),
    }


def build_security_boundary(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Describe runtime security behavior without inspecting security software."""
    findings = config_input_assurance(cfg)
    return {
        "schema": SECURITY_BOUNDARY_SCHEMA,
        "runtime_flags": {
            "runtime_download_and_execute": False,
            "persistence_installation": False,
            "security_setting_changes": False,
            "execution_policy_bypass": False,
            "automatic_exclusions": False,
        },
        "current_host_is_windows": is_windows_host(),
        "security_software_inspection": "not_performed",
        "config_security_findings": findings.get("findings", []),
        "note": "BotOps neither inspects nor changes endpoint-protection settings.",
    }


def support_trace_start() -> Dict[str, Any]:
    now_local = local_now().isoformat(timespec="seconds")
    return {
        "schema": "support_operation_trace_v1",
        "run_id": RUN_ID,
        "clock_sources": {"wall": "UTC/system wall clock", "duration": "time.monotonic"},
        "started_at_utc": utc_stamp(),
        "started_at_local": now_local,
        "last_progress_at_utc": utc_stamp(),
        "last_successful_step": "trace_initialized",
        "steps": [],
        "_started_monotonic": time.monotonic(),
    }


def support_collect(
    trace: Dict[str, Any],
    name: str,
    collector: Any,
    fallback: Any,
) -> Any:
    """Run one local support collector and isolate noncritical failure."""
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
        log_event(f"Support collector failed: {name}: {error}", "WARNING")
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


def support_trace_finish(
    trace: Dict[str, Any],
    *,
    terminal_status: str,
    shutdown_reason: str,
) -> Dict[str, Any]:
    finished = copy.deepcopy(trace)
    started = float(finished.pop("_started_monotonic", time.monotonic()))
    finished["ended_at_utc"] = utc_stamp()
    finished["ended_at_local"] = local_now().isoformat(timespec="seconds")
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
    finished["retry_summary"] = "Local metadata collectors do not retry; the no-overwrite hard-link publish is attempted once."
    return finished


def build_support_work_window_exit(
    selftest: Dict[str, Any],
    finished_trace: Dict[str, Any],
    support: Dict[str, Any],
    omissions: Sequence[str],
    *,
    fallback_used: bool,
) -> Dict[str, Any]:
    """Prepare truthful completion evidence for one local support export."""
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
    selftest_status = str(selftest.get("overall", "UNAVAILABLE")) if isinstance(selftest, dict) else "UNAVAILABLE"
    verified = [
        "report-only collectors completed with an operation trace",
        f"self-test snapshot status={selftest_status}",
        "bounded support entry plan prepared with explicit omissions",
    ]
    unverified_or_rushed: List[str] = []
    deferred: List[str] = []
    if sys.platform != "win32":
        deferred.append("live Windows start/stop-script/adopt integration was not exercised on this host")
    if fallback_used:
        unverified_or_rushed.append("advanced support plan failed; bounded minimal fallback bundle was used")
    if selftest_status not in {"PASS", "WARN"}:
        unverified_or_rushed.append(f"self-test snapshot was not usable: {selftest_status}")
    if omissions:
        deferred.extend(f"support export omission: {item}" for item in list(omissions)[:20])
    timeout_failures = [item for item in failures if "timeout" in item.get("error", "").lower()]
    other_failures = [item for item in failures if item not in timeout_failures]
    terminal = str(finished_trace.get("terminal_status", "unknown"))
    return {
        "schema": "support_work_window_exit_v1",
        "record_scope": "collector and plan status captured before atomic ZIP publication",
        "triage": {
            "critical": "report-only behavior, redaction, path/process safety, and evidence preservation",
            "high": "bounded support integrity plan, operation trace, and recovery evidence",
            "normal": "environment, launcher, and health summaries",
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
            else "No tool timeout was observed during this local support run."
        ),
        "planned_outputs": ["support ZIP"],
        "next_safe_pass": "On Windows, run preflight, launcher audit, dashboard/watch, and support export; preserve exact error text and review the newest ZIP before sharing.",
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
    if status.bot.category in {"service", "worker"} and not status.bot.launcher:
        reasons.append("service/worker folder has no safe start launcher")
    if status.control_state.startswith("OBSERVED"):
        reasons.append("running process is monitor-only unless explicitly adopted for identity tracking")
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
    limit = max(20, min(500, int(cfg.get("support_coverage_ledger_item_limit", 200))))
    root_report = build_path_targeting_report(cfg, {status.bot.name: status.bot for status in statuses})
    selftest_checks = selftest.get("checks", []) if isinstance(selftest, dict) else []
    selftest_summary = {
        "overall": selftest.get("overall", "unavailable") if isinstance(selftest, dict) else "unavailable",
        "pass": sum(1 for item in selftest_checks if item.get("status") == "PASS"),
        "warn": sum(1 for item in selftest_checks if item.get("status") == "WARN"),
        "fail": sum(1 for item in selftest_checks if item.get("status") == "FAIL"),
    }
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
            "check": "support export plan capped and reported",
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
        "scope": "effective bot root plus BotOps manager support/export collectors",
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


def support_review_summary(statuses: Sequence[BotStatus]) -> str:
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
        f"{APP_NAME} support review summary",
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
        "Control safety: force termination is disabled; start and stop-script actions are re-audited immediately before launch.",
        "Health safety: export/report/support paths are rejected; cadence learning is bounded and never triggers an automatic restart.",
        "Omission-control ledger: see status.json -> omission_control_ledger for verified/review/blocked coverage.",
        "Work-window exit: see status.json -> work_window_exit for verified, unverified, deferred, error, timeout, and next-pass evidence.",
    ]
    return "\n".join(lines) + "\n"


def cleanup_stale_temp_exports(cfg: Dict[str, Any]) -> None:
    """Remove abandoned temporary support ZIPs from prior interrupted exports."""
    retention_seconds = max(3600, int(cfg.get("support_tmp_retention_hours", 24)) * 3600)
    cutoff = time.time() - retention_seconds
    try:
        for path in exports_dir().glob("*botops_support_*.zip.tmp"):
            try:
                stat = path.stat()
                if stat.st_mtime < cutoff:
                    path.unlink(missing_ok=True)
                    log_event(f"Removed stale support temp archive: {path.name}", "WARNING")
            except Exception as exc:
                log_event(f"Could not clean support temp archive {path.name}: {exc}", "WARNING")
    except Exception as exc:
        log_event(f"Could not scan support temp archives: {exc}", "WARNING")


def _dedupe_archive_name(name: str, existing: Set[str]) -> str:
    base = safe_filename(name.replace("\\", "/").lstrip("/"))
    # Preserve folder-style support names while still removing unsafe characters
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


def support_size_limits(cfg: Dict[str, Any]) -> Tuple[int, int, int]:
    max_files = max(12, min(20, int(cfg.get("support_max_files", 20))))
    max_entry = max(
        65_536,
        min(SUPPORT_MAX_ENTRY_BYTES_HARD, int(cfg.get("support_max_entry_bytes", 1_000_000))),
    )
    max_total = max(
        max_entry,
        min(SUPPORT_MAX_TOTAL_BYTES_HARD, int(cfg.get("support_max_total_bytes", 5_000_000))),
    )
    return max_files, max_entry, max_total


def validate_support_archive_name(name: str) -> str:
    raw = str(name or "")
    posix = PurePosixPath(raw)
    windows = PureWindowsPath(raw)
    parts = posix.parts
    invalid_windows_characters = set('<>:"|?*')
    if (
        not raw
        or len(raw) > 512
        or "\x00" in raw
        or "\\" in raw
        or raw.startswith(("/", "//"))
        or posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or any(
            part in {"", ".", ".."}
            or len(part) > 120
            or part.endswith((".", " "))
            or any(character in invalid_windows_characters for character in part)
            or any(unicodedata.category(character).startswith("C") for character in part)
            or part.rstrip(" .").split(".", 1)[0].casefold() in WINDOWS_RESERVED_NAMES
            for part in parts
        )
        or str(posix) != raw
    ):
        raise RuntimeError(f"Unsafe support archive entry name: {raw!r}")
    return raw


def validate_support_plan(plan: Sequence[Tuple[str, bytes]], cfg: Dict[str, Any]) -> Tuple[List[str], int]:
    max_files, max_entry, max_total = support_size_limits(cfg)
    if len(plan) > max_files:
        raise RuntimeError(f"Support plan entry count {len(plan)} exceeds configured cap {max_files}")
    names: List[str] = []
    seen: Set[str] = set()
    total = 0
    for name, payload in plan:
        safe_name = validate_support_archive_name(name)
        marker = unicodedata.normalize("NFC", safe_name).casefold()
        if marker in seen:
            raise RuntimeError(f"Duplicate support archive entry name: {safe_name}")
        seen.add(marker)
        if not isinstance(payload, bytes):
            raise RuntimeError(f"Support archive payload must be bytes: {safe_name}")
        if len(payload) > max_entry:
            raise RuntimeError(
                f"Support entry {safe_name} exceeds configured byte cap ({len(payload)} > {max_entry})"
            )
        total += len(payload)
        if total > max_total:
            raise RuntimeError(f"Support plan exceeds configured total byte cap ({total} > {max_total})")
        names.append(safe_name)
    return names, total


def build_support_export_plan(
    cfg: Dict[str, Any],
    statuses: Sequence[BotStatus],
    selftest: Dict[str, Any],
    dashboard: str,
    launcher_audit: Dict[str, Any],
    health_audit: Dict[str, Any],
    support: Dict[str, Any],
    manager_tail: str,
) -> Tuple[List[Tuple[str, bytes]], List[str]]:
    """Build a deterministic, capped support plan before opening the ZIP."""
    max_files, max_entry_bytes, max_total_bytes = support_size_limits(cfg)
    plan: List[Tuple[str, bytes]] = []
    names: Set[str] = set()
    omissions: List[str] = []

    def add_text(arcname: str, text: str, *, required: bool = False) -> bool:
        if len(plan) >= max_files:
            message = f"omitted {arcname}: support_max_files={max_files} reached"
            omissions.append(message)
            if required:
                raise RuntimeError(f"Required support entry could not fit: {arcname}")
            return False
        clean_name = _dedupe_archive_name(arcname, names)
        safe_text = relative_sanitized_path(text, cfg)
        payload = safe_text.encode("utf-8", errors="replace")
        projected_total = sum(len(item) for _name, item in plan) + len(payload)
        if len(payload) > max_entry_bytes or projected_total > max_total_bytes:
            message = (
                f"omitted {arcname}: support byte cap reached "
                f"(entry={len(payload)}/{max_entry_bytes}, total={projected_total}/{max_total_bytes})"
            )
            omissions.append(message)
            names.discard(clean_name)
            if required:
                raise RuntimeError(f"Required support entry exceeded byte limits: {arcname}")
            return False
        plan.append((clean_name, payload))
        return True

    def upsert_text(arcname: str, text: str) -> None:
        safe_text = relative_sanitized_path(text, cfg).encode("utf-8", errors="replace")
        for index, (name, _) in enumerate(plan):
            if name == arcname:
                projected_total = sum(len(item) for position, (_entry, item) in enumerate(plan) if position != index) + len(safe_text)
                if len(safe_text) > max_entry_bytes or projected_total > max_total_bytes:
                    raise RuntimeError(f"Required support entry exceeded byte limits: {arcname}")
                plan[index] = (name, safe_text)
                return
        if not add_text(arcname, text, required=True):
            raise RuntimeError(f"Required support entry could not be added: {arcname}")

    support["export_contract"] = {
        "style": "public-support-v1",
        "max_files": max_files,
        "max_entry_bytes": max_entry_bytes,
        "max_total_bytes": max_total_bytes,
        "atomic_publish": True,
        "integrity_test_before_publish": True,
        "read_only_with_respect_to_child_projects": True,
        "read_only_with_respect_to_manager_state": True,
        "corrupt_state_recovery_suppressed": True,
        "export_refresh_registry_requested": bool(cfg.get("export_refresh_registry", False)),
        "export_refresh_registry_applied": False,
        "child_launchers_or_exports_invoked": False,
        "stale_temp_cleanup_applied": False,
        "only_write_activity": "create the managed exports directory when absent, create one temporary ZIP, integrity-test it, and atomically hard-link one new final ZIP without overwrite",
    }
    support["data_classification"] = {
        "overall": "review-before-sharing",
        "included_by_default": "redacted state summaries and launcher/health audit summaries",
        "excluded_by_default": "log bodies, process command lines, credentials, API keys, private tokens, and account identifiers",
        "review_note": "Review before sharing because bot folder names can still reveal project intent.",
    }
    support["security_boundary"] = build_security_boundary(cfg)
    support["custom_input_assurance"] = {
        "bots_root": {
            "source": "config/default/--root override",
            "effective_value": relative_sanitized_path(str(cfg.get("bots_root", DEFAULT_BOTS_ROOT)), cfg),
            "status": "recognized_validated_mapped",
            "expected_effect": "scanner limits discovery to bot folders under the configured root",
        },
        "control_mode": {
            "source": "config default enforced at load",
            "effective_value": "identity_tracked_monitoring_with_force_termination_disabled",
            "status": "recognized_validated_mapped",
            "expected_effect": "no BotOps path can force-terminate a process in the public edition",
        },
        "config": config_input_assurance(cfg),
    }
    support["resource_guardrails"] = {
        "parallel_control_actions": "serialized by project-local control-action lock",
        "support_max_files": max_files,
        "support_max_entry_bytes": max_entry_bytes,
        "support_max_total_bytes": max_total_bytes,
        "support_coverage_ledger_item_limit": int(cfg.get("support_coverage_ledger_item_limit", 200)),
        "log_rotation": "2 MB x 3 manager log files",
        "health_learning_bounds": f"{HEALTH_SAMPLE_WINDOW} intervals per bot; static threshold can only widen up to configured factor; no automatic restart action",
        "queue_backpressure": "not applicable; BotOps is a low-volume local manager without producer/consumer queues",
    }
    support["omission_control_ledger"] = build_omission_control_ledger(cfg, statuses, selftest, [])

    add_text(
        "README_SUPPORT.txt",
        textwrap.dedent(
            f"""
            {APP_NAME} support export
            Version: {APP_VERSION}
            Created UTC: {support['created_at']}
            Created local: {local_now().isoformat(timespec='seconds')}
            Run ID: {RUN_ID}

            This export excludes bot log contents by default, avoids command lines,
            redacts contextual secrets, and tokenizes user/bot-manager root paths.
            It never invokes child launchers, export scripts, maintenance scripts,
            external services, or other project code. It does not migrate, repair, rename,
            clean, or rewrite prior manager state/export evidence. The current bundle
            creates the managed exports directory only when absent, stages one
            temporary ZIP, integrity-tests and caps it, then atomically publishes
            one new final ZIP without overwriting an existing path.

            Review before sharing because bot folder names can still be sensitive.
            """
        ).strip()
        + "\n",
        required=True,
    )
    add_text("REVIEW_SUMMARY.txt", support_review_summary(statuses), required=True)
    add_text("dashboard.txt", dashboard + "\n", required=True)
    add_text("status.json", json.dumps(sanitize_for_support(support, cfg), indent=2) + "\n", required=True)
    add_text("launcher_audit.json", json.dumps(sanitize_for_support(launcher_audit, cfg), indent=2) + "\n", required=True)
    add_text("health_audit.json", json.dumps(sanitize_for_support(health_audit, cfg), indent=2) + "\n", required=True)
    add_text("selftest.json", json.dumps(sanitize_for_support(selftest, cfg), indent=2) + "\n", required=True)
    add_text("bot_manager_config.json", json.dumps(sanitize_for_support(cfg, cfg), indent=2) + "\n", required=True)
    add_text("bot_registry.json", json.dumps(sanitize_for_support(read_registry(), cfg), indent=2) + "\n", required=True)
    add_text("runtime_state.json", json.dumps(sanitize_for_support(read_runtime_state(), cfg), indent=2) + "\n", required=True)
    add_text("bot_manager_log_tail.txt", manager_tail + "\n", required=True)

    if omissions:
        # Prefer putting omissions into an existing required entry over adding a
        # separate file that would pressure the support export cap.
        summary_name = next((idx for idx, (name, _) in enumerate(plan) if name == "REVIEW_SUMMARY.txt"), None)
        if summary_name is not None:
            text = plan[summary_name][1].decode("utf-8", errors="replace")
            text += "\nExport omissions / notes:\n" + "\n".join(f"- {item}" for item in omissions) + "\n"
            plan[summary_name] = (plan[summary_name][0], text.encode("utf-8", errors="replace"))

    support["omission_control_ledger"] = build_omission_control_ledger(cfg, statuses, selftest, omissions)
    support["export_plan_final"] = {
        "entry_count": len(plan),
        "entry_names": [name for name, _ in plan],
        "max_files": max_files,
        "omission_count": len(omissions),
        "omissions": list(omissions),
        "finalized_before_zip_open": True,
    }
    upsert_text("status.json", json.dumps(sanitize_for_support(support, cfg), indent=2) + "\n")
    return plan, omissions


def build_minimal_support_export_plan(
    cfg: Dict[str, Any],
    support: Dict[str, Any],
    failures: Sequence[str],
    manager_tail: str,
) -> Tuple[List[Tuple[str, bytes]], List[str]]:
    """Create a small support bundle when an advanced collector fails."""
    max_files, max_entry_bytes, max_total_bytes = support_size_limits(cfg)
    failure_list = [redact(str(item))[:500] for item in failures if str(item).strip()][:20]
    omissions = [f"advanced export fallback: {item}" for item in failure_list]
    support["fallback_bundle"] = {
        "used": True,
        "reason_count": len(failure_list),
        "reasons": failure_list,
        "contents": "current-state summary, sanitized effective config, manager log tail when available, and recovery guidance",
    }
    support.setdefault(
        "export_contract",
        {
            "style": "public-support-v1-minimal-fallback",
            "max_files": max_files,
            "max_entry_bytes": max_entry_bytes,
            "max_total_bytes": max_total_bytes,
            "atomic_publish": True,
            "integrity_test_before_publish": True,
            "read_only_with_respect_to_child_projects": True,
            "read_only_with_respect_to_manager_state": True,
            "stale_temp_cleanup_applied": False,
            "child_launchers_or_exports_invoked": False,
        },
    )
    review = [
        f"{APP_NAME} minimal support fallback",
        f"Version: {APP_VERSION}",
        f"Run ID: {RUN_ID}",
        "",
        "Advanced collection failed, but the exporter preserved a compact report-only bundle.",
        "Failures:",
    ]
    review.extend(f"- {item}" for item in failure_list or ["unspecified advanced collector failure"])
    review.extend(
        [
            "",
            "First recovery step: run option 5 (Preflight / self-test), then option 3 (Rescan + launcher safety audit).",
            "No child project, external service, security setting, execution policy, config migration, or prior evidence was modified.",
        ]
    )
    review_text = "\n".join(review) + "\n"
    plan: List[Tuple[str, bytes]] = []

    def add_bounded(name: str, payload: bytes, *, required: bool) -> bool:
        validate_support_archive_name(name)
        projected = sum(len(item) for _entry, item in plan) + len(payload)
        if len(plan) >= max_files or len(payload) > max_entry_bytes or projected > max_total_bytes:
            omissions.append(
                f"minimal fallback omitted {name}: count/entry/total support limit reached"
            )
            if required:
                raise RuntimeError(f"Minimal fallback required entry exceeded limits: {name}")
            return False
        plan.append((name, payload))
        return True

    add_bounded("README_SUPPORT.txt", review_text.encode("utf-8"), required=True)
    add_bounded("REVIEW_SUMMARY.txt", review_text.encode("utf-8"), required=True)
    add_bounded(
        "bot_manager_config.json",
        (json.dumps(sanitize_for_support(cfg, cfg), indent=2) + "\n").encode("utf-8"),
        required=False,
    )
    if manager_tail:
        add_bounded(
            "bot_manager_log_tail.txt",
            relative_sanitized_path(manager_tail, cfg).encode("utf-8", errors="replace"),
            required=False,
        )
    final_names = [name for name, _ in plan] + ["status.json"]
    support["export_plan_final"] = {
        "entry_count": len(final_names),
        "entry_names": final_names,
        "max_files": max_files,
        "omission_count": len(omissions),
        "omissions": omissions,
        "finalized_before_zip_open": True,
        "fallback": True,
    }
    status_payload = (json.dumps(sanitize_for_support(support, cfg), indent=2) + "\n").encode("utf-8")
    if len(status_payload) > max_entry_bytes:
        compact_status = {
            "app": APP_NAME,
            "version": APP_VERSION,
            "run_id": RUN_ID,
            "fallback_bundle": support.get("fallback_bundle", {}),
            "export_contract": support.get("export_contract", {}),
            "export_plan_final": support.get("export_plan_final", {}),
            "operation_trace": support.get("operation_trace", {}),
            "collector_failures": support.get("collector_failures", []),
        }
        status_payload = (json.dumps(sanitize_for_support(compact_status, cfg), indent=2) + "\n").encode("utf-8")
    add_bounded("status.json", status_payload, required=True)
    validate_support_plan(plan, cfg)
    return plan, omissions


def write_atomic_support_zip(
    export_path: Path,
    plan: Sequence[Tuple[str, bytes]],
    cfg: Dict[str, Any],
) -> None:
    max_files, max_entry_bytes, max_total_bytes = support_size_limits(cfg)
    expected_names, expected_total = validate_support_plan(plan, cfg)
    allowed_parent = exports_dir()
    if (
        path_is_reparse_or_symlink(allowed_parent)
        or export_path.parent.resolve(strict=True) != allowed_parent.resolve(strict=True)
        or path_is_reparse_or_symlink(export_path)
        or export_path.exists()
    ):
        raise RuntimeError("Support destination must be a new regular file inside the managed exports directory.")
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{safe_filename(export_path.stem)}.{RUN_ID}.",
        suffix=".zip.tmp",
        dir=str(allowed_parent),
    )
    temp_path = Path(temp_name)
    temp_identity: Optional[os.stat_result] = None
    try:
        temp_identity = os.fstat(descriptor)
        named_identity = os.lstat(temp_path)
        if (
            not stat.S_ISREG(temp_identity.st_mode)
            or _stat_is_reparse(temp_identity)
            or _stat_is_reparse(named_identity)
            or not _same_file_identity(temp_identity, named_identity)
        ):
            raise RuntimeError("Exclusive support temp file identity could not be verified.")

        temp_stream = os.fdopen(descriptor, "w+b")
        descriptor = -1  # temp_stream now owns the descriptor
        with temp_stream:
            with zipfile.ZipFile(temp_stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for arcname, payload in plan:
                    archive.writestr(arcname, payload)
            temp_stream.flush()
            os.fsync(temp_stream.fileno())
            temp_stream.seek(0)
            with zipfile.ZipFile(temp_stream, "r") as archive:
                bad_entry = archive.testzip()
                names = archive.namelist()
                infos = archive.infolist()
            if bad_entry:
                raise RuntimeError(f"Support ZIP integrity test failed at {bad_entry}")
            actual_total = sum(info.file_size for info in infos)
            if names != expected_names or len(names) > max_files:
                raise RuntimeError("Support ZIP entries changed during write or exceeded the configured count cap.")
            if any(info.file_size > max_entry_bytes for info in infos) or actual_total != expected_total or actual_total > max_total_bytes:
                raise RuntimeError("Support ZIP entries changed size or exceeded configured byte caps.")

            before_publish = os.lstat(temp_path)
            open_identity = os.fstat(temp_stream.fileno())
            if (
                _stat_is_reparse(before_publish)
                or not stat.S_ISREG(before_publish.st_mode)
                or not _same_file_identity(temp_identity, before_publish)
                or not _same_file_identity(temp_identity, open_identity)
            ):
                raise RuntimeError("Support temp file identity changed before publication.")

            # A same-volume hard link publishes the integrity-tested inode
            # without overwriting a destination that appeared after preflight.
            os.link(temp_path, export_path, follow_symlinks=False)
            published_identity = os.lstat(export_path)
            if (
                _stat_is_reparse(published_identity)
                or not stat.S_ISREG(published_identity.st_mode)
                or not _same_file_identity(open_identity, published_identity)
            ):
                try:
                    current = os.lstat(export_path)
                    if _same_file_identity(published_identity, current):
                        export_path.unlink()
                except OSError:
                    pass
                raise RuntimeError("Published support ZIP identity did not match the verified temp file.")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            current_temp = os.lstat(temp_path)
            if temp_identity is not None and _same_file_identity(temp_identity, current_temp):
                temp_path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def export_support(cfg: Dict[str, Any]) -> Path:
    # Enforce the report-only contract even if an unexpected helper attempts a
    # state write or encounters malformed JSON. Nested callers are supported.
    with report_only_state_mode():
        return _export_support_read_only(cfg)


def _export_support_read_only(cfg: Dict[str, Any]) -> Path:
    # Export creates only the current temp/final support ZIP. It does not
    # migrate, repair, rename, clean, or rewrite prior manager/bot evidence.
    trace = support_trace_start()
    created_local = local_now()
    export_path = exports_dir() / (
        f"botops_support_v{APP_VERSION}_{local_stamp_for_filename()}_{RUN_ID[:16]}_{secrets.token_hex(4)}.zip"
    )

    bots = support_collect(trace, "scan_bots_in_memory", lambda: scan_bots(cfg, save=False), {})
    statuses = support_collect(
        trace,
        "collect_status_without_state_write",
        lambda: status_for_bots(cfg, bots, cleanup_stale=False, persist_health=False),
        [],
    )
    selftest_fallback = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "created_at": utc_stamp(),
        "overall": "UNAVAILABLE",
        "checks": [],
        "error": "self-test collector failed; see operation trace",
    }
    selftest = support_collect(trace, "run_report_only_selftest", lambda: run_selftest(cfg, bots, persist=False), selftest_fallback)
    dashboard = support_collect(
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

    launcher_audit, health_audit, audit_item_errors = support_collect(
        trace,
        "collect_launcher_and_health_audits",
        collect_bot_audits,
        ({}, {}, ["launcher/health audit collector failed"]),
    )
    if audit_item_errors and trace.get("steps"):
        trace["steps"][-1]["status"] = "partial"
        trace["steps"][-1]["error"] = "; ".join(audit_item_errors[:8])

    raw_health_snapshot = support_collect(
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
    environment_snapshot = support_collect(trace, "collect_environment_snapshot", lambda: build_environment_snapshot(cfg), {"status": "error"})
    path_targeting = support_collect(trace, "analyze_path_targeting", lambda: build_path_targeting_report(cfg, bots), {"status": "error"})
    schema_warnings = support_collect(trace, "read_schema_guards", state_schema_warnings, [])
    control_lock = support_collect(trace, "read_control_action_lock", read_control_action_lock, {"active": False, "status": "unavailable"})
    manager_tail = support_collect(
        trace,
        "read_manager_log_tail",
        lambda: tail_file(manager_log_path(), lines=250) if manager_log_path().exists() else "",
        "",
    )
    status_payload = support_collect(trace, "serialize_statuses", lambda: [status_to_dict(status) for status in statuses], [])

    support: Dict[str, Any] = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "created_at": utc_stamp(),
        "created_at_local": created_local.isoformat(timespec="seconds"),
        "run_id": RUN_ID,
        "privacy_note": "Bot log contents are excluded by default. Paths are reduced to <APP_ROOT>, <BOTS_ROOT>, and <USER_HOME> tokens.",
        "integration_review": {
            "state": "verified",
            "scope": "local_windows_process_management_only",
            "external_service_access": False,
            "secret_or_credential_access": False,
            "last_reviewed": "2026-07-18",
            "freshness_target_days": 30,
            "notes": "BotOps does not call external services or child-project export scripts. The health engine observes process identity, bounded local file metadata, and optional botops_health_v1 JSON contracts; it never restarts a project automatically.",
        },
        "control_action_lock": control_lock,
        "platform": sys.platform,
        "python": sys.version,
        "environment_snapshot": environment_snapshot,
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
        plan, omissions = build_support_export_plan(
            cfg,
            statuses,
            selftest,
            dashboard,
            launcher_audit,
            health_audit,
            support,
            manager_tail,
        )
        plan_status = "ok"
        plan_error = ""
    except Exception as exc:
        plan_status = "error"
        plan_error = redact(str(exc))
        plan_failures.append(plan_error)
        fallback_used = True
        plan, omissions = build_minimal_support_export_plan(cfg, support, plan_failures, manager_tail)
        log_event(f"Advanced support plan failed; minimal fallback used: {plan_error}", "WARNING")
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
    finished_trace = support_trace_finish(
        trace,
        terminal_status=terminal,
        shutdown_reason="normal_report_only_export_completion",
    )
    support["operation_trace"] = finished_trace
    support["collector_failures"] = [
        {"name": step.get("name"), "status": step.get("status"), "error": step.get("error", "")}
        for step in finished_trace.get("steps", [])
        if step.get("status") != "ok"
    ]
    support["fallback_bundle_used"] = fallback_used
    support["work_window_exit"] = build_support_work_window_exit(
        selftest,
        finished_trace,
        support,
        omissions,
        fallback_used=fallback_used,
    )

    # The plan builder serializes status.json before the operation trace is
    # final. Replace only that in-memory payload; no prior file is rewritten.
    status_bytes = (json.dumps(sanitize_for_support(support, cfg), indent=2) + "\n").encode("utf-8")
    status_index = next((index for index, (name, _) in enumerate(plan) if name == "status.json"), None)
    if status_index is None:
        if len(plan) >= support_size_limits(cfg)[0]:
            raise RuntimeError("Support plan has no status.json and no remaining support export slot")
        plan.append(("status.json", status_bytes))
    else:
        plan[status_index] = ("status.json", status_bytes)

    validate_support_plan(plan, cfg)
    write_atomic_support_zip(
        export_path,
        plan,
        cfg,
    )
    log_event(
        f"Support export created: {export_path} entries={len(plan)} omissions={len(omissions)} "
        f"fallback={fallback_used}"
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
        print("  [number] Manage bot   R Rescan/safety audit   W Live dashboard   D Export support")
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
        elif lower in {"d", "support", "export"}:
            export_path = export_support(cfg)
            pause(f"Support export created:\n{export_path}")
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
    subparsers.add_parser("export", help="Create safe support ZIP")
    subparsers.add_parser("open-root", help="Open bots root")
    subparsers.add_parser("open-logs", help="Open manager logs")
    subparsers.add_parser("config", help="Show state/config paths")

    start_parser = subparsers.add_parser("start", help="Start a bot by number/name/partial name")
    start_parser.add_argument("bot")
    start_parser.add_argument("--yes", action="store_true")
    start_parser.add_argument("--allow-duplicate", action="store_true", help="Override duplicate-instance protection")

    stop_parser = subparsers.add_parser("stop", help="Run a reviewed, project-scoped stop script")
    stop_parser.add_argument("bot")
    stop_parser.add_argument("--yes", action="store_true")

    adopt_parser = subparsers.add_parser("adopt", help="Adopt observed external process roots")
    adopt_parser.add_argument("bot")
    adopt_parser.add_argument("--yes", action="store_true")

    tail_parser = subparsers.add_parser("tail", help="Tail selected operational log")
    tail_parser.add_argument("bot")
    tail_parser.add_argument("--lines", type=int, default=80)

    args = parser.parse_args(argv)
    command = args.command or "menu"
    # Support export must be report-only. Load effective config without
    # persisting schema migrations so export cannot mutate config/state before
    # it produces the handoff ZIP. Other commands keep the normal migration path.
    if command == "export":
        with report_only_state_mode():
            cfg = load_config(
                root_override=args.root,
                persist_migrations=False,
                recover_corrupt=False,
            )
    else:
        cfg = load_config(root_override=args.root)
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
            export_path = export_support(cfg)
            print(export_path)
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
                return 0 if stop_bot(bot, cfg, args.yes) else 1
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
