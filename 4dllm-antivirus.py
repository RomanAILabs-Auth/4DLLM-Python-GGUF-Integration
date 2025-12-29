#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright Daniel Harding - RomanAILabs
# Credits: OpenAI GPT-5.2 Thinking
"""
4DLLM Intent Guard — GUI Scanner (Static Analysis)
==================================================

What this does
- Loads a .4dllm file and extracts embedded Python modules + metadata (NO EXECUTION).
- Runs static checks for malware-ish behaviors: subprocess, network, file-writes, obfuscation, eval/exec, etc.
- Produces a risk score + human-readable findings + exportable JSON report.

Format support
- 4DLLM v1 (sequential sections) — matches legacy builder layout.
- 4DLLM v2 (TOC-based sections) — matches newer runner layout.

This is NOT a replacement for a real AV engine.
It's a practical "intent + capability" scanner for injected Python modules inside 4DLLM packages.

Usage
  python3 4dllm_intent_guard_gui.py
"""

from __future__ import annotations

import ast
import json
import os
import re
import struct
import time
import zlib
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText


# ----------------------------
# 4DLLM Constants (shared)
# ----------------------------

FOURDLLM_MAGIC = b"4DLL"
FOURDLLM_HEADER_SIZE = 64

SECTION_GGUF_DATA = 0x01
SECTION_PYTHON_SCRIPT = 0x02
SECTION_METADATA = 0x03
SECTION_SCRIPT_CONFIG = 0x04

# v2 TOC constants (runner-style)
TOC_MAGIC = b"TOC1"
TOC_VERSION = 1
FLAG_COMPRESSED_ZLIB = 0x01

# v1 section header (builder-style): type (1B), compressed (1B), pad (2), data_size (8), extra_size (4)
V1_SECTION_HDR = struct.Struct("<BB2xQI")

# v2 section header (runner-style): type, flags, size_c, size_u, extra_sz, crc32(u)
V2_SECTION_HDR = struct.Struct("<BB2xQQII")
V2_TOC_HDR = struct.Struct("<4sII")
V2_TOC_ENTRY = struct.Struct("<BB2xQQQII")


# ----------------------------
# UI Theme
# ----------------------------

COLORS = {
    "bg_primary": "#121212",
    "bg_secondary": "#1b1b1b",
    "bg_tertiary": "#252525",
    "fg_primary": "#f2f2f2",
    "fg_secondary": "#c9c9c9",
    "muted": "#9a9a9a",
    "accent": "#3ea6ff",
    "accent_2": "#7c4dff",
    "good": "#2ecc71",
    "warn": "#f39c12",
    "bad": "#e74c3c",
    "border": "#2c2c2c",
}


# ----------------------------
# Data Models
# ----------------------------

@dataclass
class ScriptBlob:
    name: str
    source: str
    priority: int = 0
    enabled: bool = True
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ParseResult:
    path: Path
    version: int
    size_bytes: int
    gguf_present: bool
    gguf_crc_or_hash: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    script_config: Dict[str, Any] = field(default_factory=dict)
    scripts: List[ScriptBlob] = field(default_factory=list)
    parse_warnings: List[str] = field(default_factory=list)
    parse_errors: List[str] = field(default_factory=list)


@dataclass
class Finding:
    severity: str  # "LOW" | "MED" | "HIGH" | "CRITICAL"
    category: str
    title: str
    message: str
    evidence: str
    script_name: str = ""
    weight: int = 0


@dataclass
class ScanReport:
    file_info: Dict[str, Any]
    risk_score: int
    risk_label: str
    findings: List[Dict[str, Any]]
    scripts_summary: List[Dict[str, Any]]
    created_utc: float


# ----------------------------
# Utilities
# ----------------------------

def _read_exact(f, n: int) -> bytes:
    b = f.read(n)
    if len(b) != n:
        raise EOFError(f"Expected {n} bytes, got {len(b)}")
    return b


def _safe_json_loads(b: bytes, default: Any) -> Any:
    try:
        return json.loads(b.decode("utf-8", errors="replace"))
    except Exception:
        return default


def _sanitize_name(name: str) -> str:
    name = (name or "").strip()
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^a-zA-Z0-9._ -]+", "_", name)
    return name or "unnamed"


def _crc32_bytes(b: bytes) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF


def _sha256_file(path: Path, max_bytes: Optional[int] = None) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        remaining = max_bytes
        while True:
            if remaining is None:
                chunk = f.read(1024 * 1024)
            else:
                if remaining <= 0:
                    break
                chunk = f.read(min(1024 * 1024, remaining))
                remaining -= len(chunk)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _risk_label(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 15:
        return "LOW"
    return "CLEAN-ish"


# ----------------------------
# 4DLLM Parsing (v1 + v2)
# ----------------------------

def parse_4dllm(path: Path) -> ParseResult:
    size = path.stat().st_size
    with open(path, "rb") as f:
        magic = _read_exact(f, 4)
        if magic != FOURDLLM_MAGIC:
            raise ValueError("Not a 4DLLM file (bad magic).")
        ver = struct.unpack("<I", _read_exact(f, 4))[0]
        # seek past header padding
        f.seek(FOURDLLM_HEADER_SIZE)

    if ver == 1:
        return _parse_v1(path)
    elif ver == 2:
        return _parse_v2(path)
    else:
        # best-effort: try v2 then v1
        pr = ParseResult(
            path=path, version=ver, size_bytes=size, gguf_present=False,
            parse_warnings=[f"Unknown 4DLLM version {ver}; attempting v2 parse then v1 parse."]
        )
        try:
            v2 = _parse_v2(path)
            v2.parse_warnings.insert(0, pr.parse_warnings[0])
            return v2
        except Exception as e2:
            pr.parse_warnings.append(f"v2 parse failed: {e2}")
        try:
            v1 = _parse_v1(path)
            v1.parse_warnings.insert(0, pr.parse_warnings[0])
            v1.parse_warnings.append(f"v2 parse failed: {pr.parse_warnings[-1]}")
            return v1
        except Exception as e1:
            pr.parse_errors.append(f"v1 parse failed: {e1}")
            return pr


def _parse_v1(path: Path) -> ParseResult:
    pr = ParseResult(
        path=path,
        version=1,
        size_bytes=path.stat().st_size,
        gguf_present=False,
    )

    offset = FOURDLLM_HEADER_SIZE
    script_blobs: List[ScriptBlob] = []
    metadata: Dict[str, Any] = {}
    script_config: Dict[str, Any] = {}

    with open(path, "rb") as f:
        f.seek(offset)
        while True:
            hdr = f.read(V1_SECTION_HDR.size)
            if not hdr:
                break
            if len(hdr) != V1_SECTION_HDR.size:
                pr.parse_warnings.append("Truncated v1 section header; stopping.")
                break

            stype, compressed_flag, data_sz, extra_sz = V1_SECTION_HDR.unpack(hdr)
            extra_bytes = f.read(extra_sz) if extra_sz else b"{}"
            extra = _safe_json_loads(extra_bytes, default={})
            payload = f.read(data_sz) if data_sz else b""

            if len(payload) != data_sz:
                pr.parse_warnings.append(f"Truncated v1 section payload (type={stype:#x}); stopping.")
                break

            if compressed_flag:
                try:
                    payload = zlib.decompress(payload)
                except Exception as e:
                    pr.parse_warnings.append(f"Failed to decompress v1 section type={stype:#x}: {e}")

            if stype == SECTION_METADATA:
                metadata = _safe_json_loads(payload, default={}) if payload else {}
            elif stype == SECTION_SCRIPT_CONFIG:
                script_config = _safe_json_loads(payload, default={}) if payload else {}
            elif stype == SECTION_PYTHON_SCRIPT:
                name = _sanitize_name(str(extra.get("name") or "module.py"))
                src = payload.decode("utf-8", errors="replace")
                script_blobs.append(ScriptBlob(name=name, source=src, extra=extra))
            elif stype == SECTION_GGUF_DATA:
                pr.gguf_present = True
                # v1 has no CRC; provide partial hash of the file as a whole (fast) and mark it.
                # This is intentionally "lightweight" to avoid huge reads.
                pr.gguf_crc_or_hash = f"file_sha256_first64mb:{_sha256_file(path, max_bytes=64 * 1024 * 1024)}"

    # map script_config (if any) onto scripts
    cfg_by_name: Dict[str, Dict[str, Any]] = {}
    for item in (script_config.get("scripts") or []):
        if isinstance(item, dict) and "name" in item:
            cfg_by_name[str(item["name"])] = item

    for s in script_blobs:
        cfg = cfg_by_name.get(s.name) or cfg_by_name.get(s.name.replace(".py", "")) or {}
        if cfg:
            s.priority = int(cfg.get("priority", 0) or 0)
            s.enabled = bool(cfg.get("enabled", True))
        else:
            # if builder stored base name without ".py"
            cfg2 = cfg_by_name.get(s.name.replace(".py", ""))
            if cfg2:
                s.priority = int(cfg2.get("priority", 0) or 0)
                s.enabled = bool(cfg2.get("enabled", True))

    # prefer enabled scripts
    script_blobs = [s for s in script_blobs if s.enabled]
    script_blobs.sort(key=lambda x: (x.priority, x.name), reverse=True)

    pr.metadata = metadata
    pr.script_config = script_config
    pr.scripts = script_blobs
    return pr


def _find_toc_offset(path: Path, scan_back_bytes: int = 4 * 1024 * 1024) -> int:
    size = path.stat().st_size
    start = max(0, size - scan_back_bytes)
    with open(path, "rb") as f:
        f.seek(start)
        chunk = f.read(size - start)
    idx = chunk.rfind(TOC_MAGIC)
    if idx < 0:
        raise ValueError("TOC not found (TOC1).")
    return start + idx


def _parse_v2(path: Path) -> ParseResult:
    pr = ParseResult(
        path=path,
        version=2,
        size_bytes=path.stat().st_size,
        gguf_present=False,
    )

    # header sanity
    with open(path, "rb") as f:
        f.seek(0)
        magic = _read_exact(f, 4)
        if magic != FOURDLLM_MAGIC:
            raise ValueError("Not a 4DLLM file (bad magic).")
        ver = struct.unpack("<I", _read_exact(f, 4))[0]
        if ver != 2:
            raise ValueError(f"Not v2 (header says {ver}).")

    toc_off = _find_toc_offset(path)
    entries: List[Tuple[int, int, int, int, int, int, int]] = []

    with open(path, "rb") as f:
        f.seek(toc_off)
        hdr = _read_exact(f, V2_TOC_HDR.size)
        magic, toc_ver, count = V2_TOC_HDR.unpack(hdr)
        if magic != TOC_MAGIC:
            raise ValueError("Bad TOC magic.")
        if toc_ver != TOC_VERSION:
            raise ValueError(f"Unsupported TOC version: {toc_ver}")

        entries_bytes = _read_exact(f, V2_TOC_ENTRY.size * count)
        footer_crc = struct.unpack("<I", _read_exact(f, 4))[0]
        computed = _crc32_bytes(hdr + entries_bytes)
        if computed != footer_crc:
            raise ValueError("TOC CRC mismatch.")

        for i in range(count):
            chunk = entries_bytes[i * V2_TOC_ENTRY.size:(i + 1) * V2_TOC_ENTRY.size]
            stype, flags, off, size_c, size_u, extra_sz, crc_u = V2_TOC_ENTRY.unpack(chunk)
            entries.append((stype, flags, off, size_c, size_u, extra_sz, crc_u))

    metadata: Dict[str, Any] = {}
    script_config: Dict[str, Any] = {}
    scripts: List[ScriptBlob] = []

    # helper read+decode
    def read_section(stype: int, flags: int, off: int, size_c: int, size_u: int, extra_sz: int, crc_u: int) -> Tuple[Dict[str, Any], bytes]:
        with open(path, "rb") as f:
            f.seek(off)
            sh = _read_exact(f, V2_SECTION_HDR.size)
            _stype2, _flags2, _size_c2, _size_u2, _extra_sz2, _crc_u2 = V2_SECTION_HDR.unpack(sh)
            if (_stype2, _flags2, _size_c2, _size_u2, _extra_sz2, _crc_u2) != (stype, flags, size_c, size_u, extra_sz, crc_u):
                raise ValueError("Section header mismatch vs TOC.")
            extra_bytes = _read_exact(f, extra_sz) if extra_sz else b"{}"
            extra = _safe_json_loads(extra_bytes, default={})
            payload_c = _read_exact(f, size_c) if size_c else b""

        data = payload_c
        if flags & FLAG_COMPRESSED_ZLIB:
            data = zlib.decompress(data)

        c = _crc32_bytes(data)
        if c != crc_u:
            raise ValueError(f"CRC mismatch for section {stype:#x} (expected {crc_u:08x}, got {c:08x}).")
        if len(data) != size_u:
            raise ValueError("Decoded size mismatch.")
        return extra, data

    # parse sections
    for (stype, flags, off, size_c, size_u, extra_sz, crc_u) in entries:
        try:
            if stype == SECTION_GGUF_DATA:
                pr.gguf_present = True
                # provide a stable "file hash" + gguf crc (already stored)
                pr.gguf_crc_or_hash = f"gguf_crc32:{crc_u:08x} file_sha256_first64mb:{_sha256_file(path, max_bytes=64 * 1024 * 1024)}"
            elif stype == SECTION_METADATA:
                _extra, data = read_section(stype, flags, off, size_c, size_u, extra_sz, crc_u)
                metadata = _safe_json_loads(data, default={})
            elif stype == SECTION_SCRIPT_CONFIG:
                _extra, data = read_section(stype, flags, off, size_c, size_u, extra_sz, crc_u)
                script_config = _safe_json_loads(data, default={})
            elif stype == SECTION_PYTHON_SCRIPT:
                extra, data = read_section(stype, flags, off, size_c, size_u, extra_sz, crc_u)
                name = _sanitize_name(str(extra.get("name") or extra.get("filename") or "module.py"))
                src = data.decode("utf-8", errors="replace")
                scripts.append(ScriptBlob(name=name, source=src, extra=extra))
        except Exception as e:
            pr.parse_warnings.append(f"Failed to parse section type={stype:#x} @ {off}: {e}")

    # map priorities/enabled from config if present
    cfg_by_name: Dict[str, Dict[str, Any]] = {}
    for item in (script_config.get("scripts") or []):
        if isinstance(item, dict) and "name" in item:
            cfg_by_name[str(item["name"])] = item

    for s in scripts:
        cfg = cfg_by_name.get(s.name) or cfg_by_name.get(s.name.replace(".py", "")) or {}
        if cfg:
            s.priority = int(cfg.get("priority", s.extra.get("priority", 0)) or 0)
            s.enabled = bool(cfg.get("enabled", True))
        else:
            s.priority = int(s.extra.get("priority", 0) or 0)
            s.enabled = True

    scripts = [s for s in scripts if s.enabled]
    scripts.sort(key=lambda x: (x.priority, x.name), reverse=True)

    pr.metadata = metadata
    pr.script_config = script_config
    pr.scripts = scripts
    return pr


# ----------------------------
# Static Scanner
# ----------------------------

DANGEROUS_IMPORTS = {
    # process + OS control
    "subprocess", "os", "pty", "signal", "shlex",
    # network / exfil
    "socket", "requests", "urllib", "http", "ftplib", "smtplib", "ssl",
    # binary loading / stealth
    "ctypes", "marshal", "pickle", "importlib", "builtins",
    # filesystem traversal
    "shutil", "pathlib", "glob",
    # threading sometimes used for stealth
    "threading", "multiprocessing",
}

HIGH_RISK_CALLS = {
    "eval": 30,
    "exec": 30,
    "compile": 20,
    "__import__": 25,
    "open": 8,  # context dependent; escalated if write mode detected
}

SUSPICIOUS_STRINGS = [
    (re.compile(r"\b(base64|b64decode|binascii)\b", re.I), ("MED", 10, "Obfuscation", "Base64 usage detected")),
    (re.compile(r"\b(marshal|pickle)\b", re.I), ("HIGH", 20, "Payload", "Serialized payload tools detected")),
    (re.compile(r"\b(ctypes|windll|cdll)\b", re.I), ("HIGH", 25, "Native", "Native code loading hints detected")),
    (re.compile(r"\b(subprocess\.|os\.system|popen\()", re.I), ("HIGH", 25, "Process", "Process execution patterns detected")),
    (re.compile(r"\b(requests\.|urllib\.|socket\.)", re.I), ("HIGH", 25, "Network", "Network I/O patterns detected")),
    (re.compile(r"\b(steal|exfil|keylog|wallet|seed phrase|clipboard)\b", re.I), ("CRITICAL", 35, "Theft", "Theft/exfil keywords detected")),
    (re.compile(r"\b(cron|crontab|systemd|rc\.local|\.bashrc|startup)\b", re.I), ("HIGH", 25, "Persistence", "Persistence keywords detected")),
]

# Optional "harm intent" keyword scan (kept LOW weight to avoid tons of false positives)
CONTENT_RISK_KEYWORDS = [
    (re.compile(r"\b(?:suicide|self[- ]harm)\b", re.I), ("LOW", 5, "Content Risk", "Self-harm related keyword present")),
    (re.compile(r"\b(?:bomb|explosive|detonator)\b", re.I), ("LOW", 5, "Content Risk", "Explosives-related keyword present")),
    (re.compile(r"\b(?:bioweapon|anthrax|ricin)\b", re.I), ("LOW", 5, "Content Risk", "Bio-related keyword present")),
]


def scan_scripts(
    scripts: List[ScriptBlob],
    scan_metadata_blob: Optional[str],
    enable_content_keywords: bool,
) -> Tuple[int, List[Finding], List[Dict[str, Any]]]:
    findings: List[Finding] = []
    summary: List[Dict[str, Any]] = []

    total_weight = 0
    max_possible = 0

    for s in scripts:
        src = s.source or ""
        per_script_findings: List[Finding] = []

        # AST-based checks
        try:
            tree = ast.parse(src)
        except Exception as e:
            per_script_findings.append(Finding(
                severity="MED",
                category="Parser",
                title="AST parse failed",
                message="This module couldn't be parsed by Python AST; could be malformed or obfuscated.",
                evidence=str(e),
                script_name=s.name,
                weight=12,
            ))
            tree = None

        # import checks
        imported = set()
        if tree is not None:
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = (alias.name or "").split(".", 1)[0]
                        if top:
                            imported.add(top)
                elif isinstance(node, ast.ImportFrom):
                    top = (node.module or "").split(".", 1)[0]
                    if top:
                        imported.add(top)

        risky_imports = sorted([m for m in imported if m in DANGEROUS_IMPORTS])
        if risky_imports:
            sev = "MED" if len(risky_imports) <= 2 else "HIGH"
            w = 10 + 5 * min(len(risky_imports), 6)
            per_script_findings.append(Finding(
                severity=sev,
                category="Imports",
                title="High-risk imports",
                message="Imports that commonly enable file/process/network control.",
                evidence=", ".join(risky_imports),
                script_name=s.name,
                weight=w,
            ))

        # call checks
        def _name_of_call(n: ast.AST) -> str:
            if isinstance(n, ast.Name):
                return n.id
            if isinstance(n, ast.Attribute):
                return n.attr
            return ""

        if tree is not None:
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fname = _name_of_call(node.func)
                    if fname in HIGH_RISK_CALLS:
                        w = HIGH_RISK_CALLS[fname]
                        sev = "HIGH" if w >= 20 else "MED"
                        evidence = fname
                        # open() in write mode escalates
                        if fname == "open":
                            try:
                                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                                    mode = node.args[1].value
                                    if any(ch in mode for ch in ["w", "a", "+", "x"]):
                                        w = 18
                                        sev = "HIGH"
                                        evidence = f"open(mode={mode!r})"
                            except Exception:
                                pass

                        per_script_findings.append(Finding(
                            severity=sev,
                            category="Execution",
                            title=f"Risky call: {fname}()",
                            message="This call is commonly used for code execution or powerful I/O.",
                            evidence=evidence,
                            script_name=s.name,
                            weight=w,
                        ))

        # suspicious string heuristics
        for rx, (sev, w, cat, msg) in SUSPICIOUS_STRINGS:
            m = rx.search(src)
            if m:
                per_script_findings.append(Finding(
                    severity=sev,
                    category=cat,
                    title=msg,
                    message="Pattern match in module source.",
                    evidence=m.group(0),
                    script_name=s.name,
                    weight=w,
                ))

        # simple obfuscation score: huge base64-like blobs
        b64ish = re.findall(r"[A-Za-z0-9+/]{200,}={0,2}", src)
        if b64ish:
            per_script_findings.append(Finding(
                severity="HIGH",
                category="Obfuscation",
                title="Large base64-like blob(s)",
                message="Large opaque strings are often used to hide payloads.",
                evidence=f"count={len(b64ish)} max_len={max(len(x) for x in b64ish)}",
                script_name=s.name,
                weight=22,
            ))

        # content keyword scan (low weight, optional)
        if enable_content_keywords:
            for rx, (sev, w, cat, msg) in CONTENT_RISK_KEYWORDS:
                m = rx.search(src)
                if m:
                    per_script_findings.append(Finding(
                        severity=sev,
                        category=cat,
                        title=msg,
                        message="Keyword match in module source.",
                        evidence=m.group(0),
                        script_name=s.name,
                        weight=w,
                    ))

        # aggregate per script
        # cap per-script weight to avoid one file dominating to 100 instantly
        wsum = sum(f.weight for f in per_script_findings)
        wsum_capped = min(60, wsum)

        total_weight += wsum_capped
        max_possible += 60  # per script cap

        findings.extend(per_script_findings)

        summary.append({
            "name": s.name,
            "priority": s.priority,
            "enabled": s.enabled,
            "bytes": len(src.encode("utf-8", errors="replace")),
            "imports_detected": sorted(list(imported))[:80],
            "finding_count": len(per_script_findings),
            "script_weight_raw": wsum,
            "script_weight_capped": wsum_capped,
        })

    # optional: metadata content scan (super low)
    if scan_metadata_blob:
        if enable_content_keywords:
            for rx, (sev, w, cat, msg) in CONTENT_RISK_KEYWORDS:
                m = rx.search(scan_metadata_blob)
                if m:
                    findings.append(Finding(
                        severity=sev,
                        category=cat,
                        title=f"{msg} (metadata)",
                        message="Keyword match in metadata text.",
                        evidence=m.group(0),
                        script_name="(metadata)",
                        weight=w,
                    ))
                    total_weight += w
                    max_possible += 10

    # Convert weight -> 0..100
    if max_possible <= 0:
        score = 0
    else:
        score = int(round(100.0 * min(total_weight, max_possible) / float(max_possible)))

    # Boost if any CRITICAL exists
    if any(f.severity == "CRITICAL" for f in findings):
        score = min(100, score + 15)

    return score, sorted_findings(findings), summary


def sorted_findings(findings: List[Finding]) -> List[Finding]:
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MED": 2, "LOW": 1}
    return sorted(findings, key=lambda f: (sev_rank.get(f.severity, 0), f.weight), reverse=True)


# ----------------------------
# GUI
# ----------------------------

class IntentGuardGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("🛡️ 4DLLM Intent Guard — RomanAILabs")
        self.root.geometry("1100x760")
        self.root.configure(bg=COLORS["bg_primary"])

        self._setup_style()

        self.file_path: Optional[Path] = None
        self.parse_result: Optional[ParseResult] = None
        self.report: Optional[ScanReport] = None

        self.var_scan_metadata = tk.BooleanVar(value=True)
        self.var_content_keywords = tk.BooleanVar(value=False)
        self.var_include_first64mb_hash = tk.BooleanVar(value=True)

        self._build_layout()

    def _setup_style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("TFrame", background=COLORS["bg_primary"])
        style.configure("TLabelframe", background=COLORS["bg_primary"], foreground=COLORS["fg_primary"])
        style.configure("TLabelframe.Label", background=COLORS["bg_primary"], foreground=COLORS["fg_primary"])
        style.configure("TLabel", background=COLORS["bg_primary"], foreground=COLORS["fg_primary"])
        style.configure("TButton", padding=8)
        style.configure("TCheckbutton", background=COLORS["bg_primary"], foreground=COLORS["fg_primary"])

        style.configure("Treeview",
                        background=COLORS["bg_secondary"],
                        fieldbackground=COLORS["bg_secondary"],
                        foreground=COLORS["fg_primary"],
                        rowheight=26,
                        bordercolor=COLORS["border"],
                        borderwidth=0)
        style.map("Treeview", background=[("selected", COLORS["accent"])], foreground=[("selected", "#000000")])

        style.configure("TNotebook", background=COLORS["bg_primary"], borderwidth=0)
        style.configure("TNotebook.Tab", padding=(12, 8), background=COLORS["bg_tertiary"], foreground=COLORS["fg_primary"])
        style.map("TNotebook.Tab", background=[("selected", COLORS["bg_secondary"])])

        style.configure("Horizontal.TProgressbar", troughcolor=COLORS["bg_tertiary"], background=COLORS["accent"])

    def _build_layout(self) -> None:
        # Header
        header = tk.Frame(self.root, bg=COLORS["bg_secondary"], height=74)
        header.pack(fill="x")
        header.pack_propagate(False)

        title = tk.Label(
            header,
            text="🛡️ 4DLLM Intent Guard",
            font=("Segoe UI", 20, "bold"),
            bg=COLORS["bg_secondary"],
            fg=COLORS["accent"],
        )
        title.pack(side="left", padx=18, pady=18)

        subtitle = tk.Label(
            header,
            text="Static scanner for injected Python modules inside 4DLLM packages (no execution).",
            font=("Segoe UI", 10),
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_secondary"],
        )
        subtitle.pack(side="left", padx=10)

        # Main body: left controls + right notebook
        body = tk.Frame(self.root, bg=COLORS["bg_primary"])
        body.pack(fill="both", expand=True, padx=16, pady=14)

        left = tk.Frame(body, bg=COLORS["bg_primary"], width=330)
        left.pack(side="left", fill="y", padx=(0, 12))
        left.pack_propagate(False)

        right = tk.Frame(body, bg=COLORS["bg_primary"])
        right.pack(side="right", fill="both", expand=True)

        # Left controls
        lf_file = ttk.Labelframe(left, text="📦 Target 4DLLM", padding=12)
        lf_file.pack(fill="x", pady=(0, 12))

        self.lbl_file = tk.Label(
            lf_file,
            text="No file selected.",
            font=("Segoe UI", 10),
            bg=COLORS["bg_primary"],
            fg=COLORS["muted"],
            justify="left",
            anchor="w",
            wraplength=290,
        )
        self.lbl_file.pack(fill="x", pady=(0, 10))

        btn_pick = tk.Button(
            lf_file,
            text="📂 Choose .4dllm",
            command=self.pick_file,
            bg=COLORS["accent"],
            fg="#000000",
            relief="flat",
            padx=14,
            pady=10,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
        )
        btn_pick.pack(fill="x")

        lf_opts = ttk.Labelframe(left, text="⚙️ Scan Options", padding=12)
        lf_opts.pack(fill="x", pady=(0, 12))

        cb1 = ttk.Checkbutton(lf_opts, text="Scan metadata blobs", variable=self.var_scan_metadata)
        cb1.pack(anchor="w", pady=3)

        cb2 = ttk.Checkbutton(lf_opts, text="Enable content-risk keyword scan (low weight)", variable=self.var_content_keywords)
        cb2.pack(anchor="w", pady=3)

        cb3 = ttk.Checkbutton(lf_opts, text="Compute file hash (first 64MB)", variable=self.var_include_first64mb_hash)
        cb3.pack(anchor="w", pady=3)

        lf_actions = ttk.Labelframe(left, text="🚀 Actions", padding=12)
        lf_actions.pack(fill="x", pady=(0, 12))

        self.btn_scan = tk.Button(
            lf_actions,
            text="🔎 Parse + Scan",
            command=self.run_scan,
            bg=COLORS["good"],
            fg="#000000",
            relief="flat",
            padx=14,
            pady=12,
            cursor="hand2",
            font=("Segoe UI", 11, "bold"),
        )
        self.btn_scan.pack(fill="x", pady=(0, 8))

        self.btn_export = tk.Button(
            lf_actions,
            text="💾 Export Report (JSON)",
            command=self.export_report,
            bg=COLORS["accent_2"],
            fg="#ffffff",
            relief="flat",
            padx=14,
            pady=10,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
            state="disabled",
        )
        self.btn_export.pack(fill="x")

        # Risk panel
        lf_risk = ttk.Labelframe(left, text="📊 Risk Meter", padding=12)
        lf_risk.pack(fill="x")

        self.risk_value = tk.IntVar(value=0)
        self.lbl_risk = tk.Label(
            lf_risk,
            text="Score: 0 (CLEAN-ish)",
            font=("Segoe UI", 11, "bold"),
            bg=COLORS["bg_primary"],
            fg=COLORS["fg_primary"],
            anchor="w",
        )
        self.lbl_risk.pack(fill="x", pady=(0, 8))

        self.pb = ttk.Progressbar(lf_risk, orient="horizontal", mode="determinate", maximum=100)
        self.pb.pack(fill="x")

        self.lbl_status = tk.Label(
            left,
            text="Ready.",
            font=("Segoe UI", 9),
            bg=COLORS["bg_primary"],
            fg=COLORS["fg_secondary"],
            anchor="w",
            justify="left",
            wraplength=310,
        )
        self.lbl_status.pack(fill="x", pady=(10, 0))

        # Right notebook
        self.nb = ttk.Notebook(right)
        self.nb.pack(fill="both", expand=True)

        self.tab_overview = ttk.Frame(self.nb)
        self.tab_scripts = ttk.Frame(self.nb)
        self.tab_findings = ttk.Frame(self.nb)
        self.tab_report = ttk.Frame(self.nb)

        self.nb.add(self.tab_overview, text="Overview")
        self.nb.add(self.tab_scripts, text="Scripts")
        self.nb.add(self.tab_findings, text="Findings")
        self.nb.add(self.tab_report, text="Report")

        self._build_tab_overview()
        self._build_tab_scripts()
        self._build_tab_findings()
        self._build_tab_report()

    def _build_tab_overview(self) -> None:
        frame = tk.Frame(self.tab_overview, bg=COLORS["bg_primary"])
        frame.pack(fill="both", expand=True, padx=14, pady=14)

        self.txt_overview = ScrolledText(
            frame,
            height=10,
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_primary"],
            insertbackground=COLORS["fg_primary"],
            font=("Consolas", 10),
            relief="flat",
        )
        self.txt_overview.pack(fill="both", expand=True)

    def _build_tab_scripts(self) -> None:
        frame = tk.Frame(self.tab_scripts, bg=COLORS["bg_primary"])
        frame.pack(fill="both", expand=True, padx=14, pady=14)

        cols = ("priority", "bytes", "findings", "imports")
        self.tv_scripts = ttk.Treeview(frame, columns=cols, show="headings", height=18)
        self.tv_scripts.heading("priority", text="Priority")
        self.tv_scripts.heading("bytes", text="Bytes")
        self.tv_scripts.heading("findings", text="Findings")
        self.tv_scripts.heading("imports", text="Top Imports (detected)")

        self.tv_scripts.column("priority", width=80, anchor="center")
        self.tv_scripts.column("bytes", width=90, anchor="center")
        self.tv_scripts.column("findings", width=90, anchor="center")
        self.tv_scripts.column("imports", width=520, anchor="w")

        self.tv_scripts.pack(fill="both", expand=True)

        self.tv_scripts.bind("<<TreeviewSelect>>", self._on_script_select)

        self.txt_script_view = ScrolledText(
            frame,
            height=12,
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_primary"],
            insertbackground=COLORS["fg_primary"],
            font=("Consolas", 10),
            relief="flat",
        )
        self.txt_script_view.pack(fill="both", expand=True, pady=(12, 0))

    def _build_tab_findings(self) -> None:
        frame = tk.Frame(self.tab_findings, bg=COLORS["bg_primary"])
        frame.pack(fill="both", expand=True, padx=14, pady=14)

        cols = ("severity", "category", "script", "title", "weight")
        self.tv_findings = ttk.Treeview(frame, columns=cols, show="headings", height=18)
        for c, t, w in [
            ("severity", "Severity", 90),
            ("category", "Category", 120),
            ("script", "Script", 180),
            ("title", "Title", 420),
            ("weight", "Weight", 70),
        ]:
            self.tv_findings.heading(c, text=t)
            self.tv_findings.column(c, width=w, anchor="w" if c in ("category", "script", "title") else "center")

        self.tv_findings.pack(fill="both", expand=True)
        self.tv_findings.bind("<<TreeviewSelect>>", self._on_finding_select)

        self.txt_finding_detail = ScrolledText(
            frame,
            height=12,
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_primary"],
            insertbackground=COLORS["fg_primary"],
            font=("Consolas", 10),
            relief="flat",
        )
        self.txt_finding_detail.pack(fill="both", expand=True, pady=(12, 0))

    def _build_tab_report(self) -> None:
        frame = tk.Frame(self.tab_report, bg=COLORS["bg_primary"])
        frame.pack(fill="both", expand=True, padx=14, pady=14)

        self.txt_report = ScrolledText(
            frame,
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_primary"],
            insertbackground=COLORS["fg_primary"],
            font=("Consolas", 10),
            relief="flat",
        )
        self.txt_report.pack(fill="both", expand=True)

    # ----------------------------
    # Actions
    # ----------------------------

    def set_status(self, msg: str) -> None:
        self.lbl_status.config(text=msg)
        self.root.update_idletasks()

    def pick_file(self) -> None:
        fp = filedialog.askopenfilename(
            title="Select a 4DLLM file",
            filetypes=[("4DLLM files", "*.4dllm"), ("All files", "*.*")]
        )
        if not fp:
            return
        self.file_path = Path(fp).expanduser().resolve()
        self.lbl_file.config(text=str(self.file_path), fg=COLORS["fg_primary"])
        self.set_status("File selected. Ready to scan.")
        self._clear_views()
        self.btn_export.config(state="disabled")

    def _clear_views(self) -> None:
        self.txt_overview.delete("1.0", "end")
        self.txt_script_view.delete("1.0", "end")
        self.txt_finding_detail.delete("1.0", "end")
        self.txt_report.delete("1.0", "end")

        for tv in (self.tv_scripts, self.tv_findings):
            for item in tv.get_children():
                tv.delete(item)

        self.pb["value"] = 0
        self.lbl_risk.config(text="Score: 0 (CLEAN-ish)", fg=COLORS["fg_primary"])
        self.risk_value.set(0)

    def run_scan(self) -> None:
        if not self.file_path:
            messagebox.showwarning("No file", "Pick a .4dllm file first.")
            return

        self._clear_views()
        self.set_status("Parsing 4DLLM...")
        self.pb["value"] = 10
        self.root.update_idletasks()

        try:
            pr = parse_4dllm(self.file_path)
            self.parse_result = pr
        except Exception as e:
            messagebox.showerror("Parse failed", str(e))
            self.set_status(f"Parse failed: {e}")
            return

        self.pb["value"] = 25
        self.root.update_idletasks()

        # Optional extra hash
        if self.var_include_first64mb_hash.get():
            self.set_status("Hashing (first 64MB) ...")
            try:
                h = _sha256_file(self.file_path, max_bytes=64 * 1024 * 1024)
                # Keep existing gguf_crc_or_hash if present; append.
                if pr.gguf_crc_or_hash:
                    pr.gguf_crc_or_hash = f"{pr.gguf_crc_or_hash} file_sha256_first64mb:{h}"
                else:
                    pr.gguf_crc_or_hash = f"file_sha256_first64mb:{h}"
            except Exception as e:
                pr.parse_warnings.append(f"Hash failed: {e}")

        self.pb["value"] = 40
        self.root.update_idletasks()

        # Scan
        self.set_status("Scanning scripts (static analysis) ...")
        meta_blob = None
        if self.var_scan_metadata.get():
            try:
                meta_blob = json.dumps(pr.metadata, ensure_ascii=False)
            except Exception:
                meta_blob = str(pr.metadata)

        score, findings, scripts_summary = scan_scripts(
            pr.scripts,
            scan_metadata_blob=meta_blob,
            enable_content_keywords=bool(self.var_content_keywords.get()),
        )

        self.pb["value"] = 85
        self.root.update_idletasks()

        label = _risk_label(score)
        self._update_risk_meter(score, label)

        self._populate_overview(pr, score, label)
        self._populate_scripts(pr, scripts_summary)
        self._populate_findings(findings)
        self._populate_report(pr, score, label, findings, scripts_summary)

        self.pb["value"] = 100
        self.set_status("Done. Review tabs + export JSON report if needed.")
        self.btn_export.config(state="normal")

    def _update_risk_meter(self, score: int, label: str) -> None:
        self.risk_value.set(score)
        self.pb["value"] = score

        if label in ("CRITICAL", "HIGH"):
            color = COLORS["bad"]
        elif label == "MEDIUM":
            color = COLORS["warn"]
        elif label == "LOW":
            color = COLORS["accent"]
        else:
            color = COLORS["good"]

        self.lbl_risk.config(text=f"Score: {score} ({label})", fg=color)

    def export_report(self) -> None:
        if not self.report:
            messagebox.showwarning("No report", "Run a scan first.")
            return

        out = filedialog.asksaveasfilename(
            title="Save JSON report",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")]
        )
        if not out:
            return

        try:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(self.report.__dict__, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Saved", f"Report saved:\n{out}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    # ----------------------------
    # Populate tabs
    # ----------------------------

    def _populate_overview(self, pr: ParseResult, score: int, label: str) -> None:
        lines = []
        lines.append("4DLLM Intent Guard — Overview")
        lines.append("=" * 38)
        lines.append(f"File: {pr.path}")
        lines.append(f"Size: {pr.size_bytes:,} bytes")
        lines.append(f"Version: {pr.version}")
        lines.append(f"GGUF Present: {pr.gguf_present}")
        lines.append(f"GGUF/Hash: {pr.gguf_crc_or_hash or 'n/a'}")
        lines.append("")
        lines.append(f"Risk Score: {score} / 100  =>  {label}")
        lines.append("")
        lines.append(f"Scripts (enabled): {len(pr.scripts)}")
        if pr.metadata:
            lines.append(f"Metadata keys: {len(pr.metadata.keys())}")
        else:
            lines.append("Metadata keys: 0")
        if pr.script_config:
            lines.append(f"Script config keys: {len(pr.script_config.keys())}")
        else:
            lines.append("Script config keys: 0")

        if pr.parse_warnings:
            lines.append("")
            lines.append("Warnings:")
            for w in pr.parse_warnings[:30]:
                lines.append(f"  - {w}")
            if len(pr.parse_warnings) > 30:
                lines.append(f"  ... +{len(pr.parse_warnings) - 30} more")

        if pr.parse_errors:
            lines.append("")
            lines.append("Errors:")
            for e in pr.parse_errors[:30]:
                lines.append(f"  - {e}")

        self.txt_overview.insert("1.0", "\n".join(lines))

    def _populate_scripts(self, pr: ParseResult, scripts_summary: List[Dict[str, Any]]) -> None:
        # map for quick lookup
        by_name = {s["name"]: s for s in scripts_summary}

        for s in pr.scripts:
            sm = by_name.get(s.name, {})
            imports = ", ".join((sm.get("imports_detected") or [])[:12])
            self.tv_scripts.insert(
                "",
                "end",
                iid=s.name,
                values=(
                    str(s.priority),
                    str(len(s.source.encode("utf-8", errors="replace"))),
                    str(sm.get("finding_count", 0)),
                    imports,
                ),
            )

    def _populate_findings(self, findings: List[Finding]) -> None:
        for i, f in enumerate(findings):
            iid = f"f{i}"
            self.tv_findings.insert(
                "",
                "end",
                iid=iid,
                values=(f.severity, f.category, f.script_name, f.title, str(f.weight)),
            )

        # store for selection details
        self._finding_cache = findings

    def _populate_report(self, pr: ParseResult, score: int, label: str, findings: List[Finding], scripts_summary: List[Dict[str, Any]]) -> None:
        file_info = {
            "path": str(pr.path),
            "size_bytes": pr.size_bytes,
            "version": pr.version,
            "gguf_present": pr.gguf_present,
            "gguf_crc_or_hash": pr.gguf_crc_or_hash,
            "script_count_enabled": len(pr.scripts),
            "metadata_present": bool(pr.metadata),
            "script_config_present": bool(pr.script_config),
            "parse_warnings": pr.parse_warnings,
            "parse_errors": pr.parse_errors,
        }

        findings_dicts = []
        for f in findings:
            findings_dicts.append({
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "message": f.message,
                "evidence": f.evidence,
                "script_name": f.script_name,
                "weight": f.weight,
            })

        rep = ScanReport(
            file_info=file_info,
            risk_score=score,
            risk_label=label,
            findings=findings_dicts,
            scripts_summary=scripts_summary,
            created_utc=time.time(),
        )
        self.report = rep

        pretty = json.dumps(rep.__dict__, indent=2, ensure_ascii=False)
        self.txt_report.insert("1.0", pretty)

    # ----------------------------
    # Selection handlers
    # ----------------------------

    def _on_script_select(self, _evt=None) -> None:
        if not self.parse_result:
            return
        sel = self.tv_scripts.selection()
        if not sel:
            return
        name = sel[0]
        script = next((s for s in self.parse_result.scripts if s.name == name), None)
        if not script:
            return
        self.txt_script_view.delete("1.0", "end")
        header = f"# {script.name} (priority={script.priority})\n# ---\n\n"
        self.txt_script_view.insert("1.0", header + script.source)

    def _on_finding_select(self, _evt=None) -> None:
        sel = self.tv_findings.selection()
        if not sel:
            return
        iid = sel[0]
        try:
            idx = int(iid[1:])
        except Exception:
            return
        if not hasattr(self, "_finding_cache"):
            return
        findings: List[Finding] = getattr(self, "_finding_cache")
        if idx < 0 or idx >= len(findings):
            return
        f = findings[idx]
        self.txt_finding_detail.delete("1.0", "end")
        block = []
        block.append(f"Severity : {f.severity}")
        block.append(f"Category : {f.category}")
        block.append(f"Script   : {f.script_name}")
        block.append(f"Weight   : {f.weight}")
        block.append("")
        block.append(f"Title    : {f.title}")
        block.append("")
        block.append(f"Message  : {f.message}")
        block.append("")
        block.append("Evidence :")
        block.append(f"{f.evidence}")
        self.txt_finding_detail.insert("1.0", "\n".join(block))


def main() -> None:
    root = tk.Tk()
    app = IntentGuardGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

