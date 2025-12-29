#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Copyright Daniel Harding - RomanAILabs
Credits: Built with assistance from OpenAI (GPT-5.2 Thinking)

4DLLM Runner (Terminal) — v0.3.0

Fixes vs v0.2.0:
- ✅ Fix "No module named nebula_life_module" by:
  - Pre-registering ALL injected modules in sys.modules under plain + namespaced names
  - Sorting module load order by detected intra-module imports (dependency-first)
- ✅ Keeps Python 3.12 dataclasses happy (real modules in sys.modules)
- ✅ Streams GGUF extraction (no multi-GB RAM load)

Usage:
  cd ~/Documents/FusionTrainer
  python3 4dllm_runner.py --file ~/Desktop/prototype.4dllm --backend llama_cpp --unsafe-modules

Safe mode (restricted imports) example:
  python3 4dllm_runner.py --file ~/Desktop/prototype.4dllm --backend llama_cpp --allow-import os,sys,pathlib

Notes:
- Your modules are heavy (numpy/flask/qiskit). --unsafe-modules is expected for now.
"""

from __future__ import annotations

import argparse
import ast
import builtins
import json
import os
import re
import struct
import sys
import tempfile
import time
import types
import zlib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set


# ---------------- 4DLLM Format (must match Builder v2) ----------------

FOURDLLM_MAGIC = b"4DLL"
FOURDLLM_HEADER_SIZE = 64
FOURDLLM_VERSION_EXPECTED = 2

TOC_MAGIC = b"TOC1"
TOC_VERSION = 1

SECTION_GGUF_DATA = 0x01
SECTION_PYTHON_SCRIPT = 0x02
SECTION_METADATA = 0x03
SECTION_SCRIPT_CONFIG = 0x04

FLAG_COMPRESSED_ZLIB = 0x01

SECTION_HDR_STRUCT = struct.Struct("<BB2xQQII")   # type, flags, size_c, size_u, extra_sz, crc32(u)
TOC_HDR_STRUCT = struct.Struct("<4sII")          # magic, toc_version, section_count
TOC_ENTRY_STRUCT = struct.Struct("<BB2xQQQII")   # type, flags, offset, size_c, size_u, extra_sz, crc32(u)


# ---------------- Helpers ----------------

def eprint(*a: Any) -> None:
    print(*a, file=sys.stderr)


def read_exact(f, n: int) -> bytes:
    b = f.read(n)
    if len(b) != n:
        raise EOFError(f"Expected {n} bytes, got {len(b)}")
    return b


def crc32_bytes(b: bytes) -> int:
    return zlib.crc32(b) & 0xFFFFFFFF


def safe_json_loads(b: bytes, default: Any) -> Any:
    try:
        return json.loads(b.decode("utf-8", errors="replace"))
    except Exception:
        return default


def sanitize_filename(name: str) -> str:
    name = (name or "").strip().replace("\\", "/")
    name = name.split("/")[-1]
    name = re.sub(r"[^a-zA-Z0-9._-]+", "_", name)
    return name or "unnamed.py"


def sanitize_modname_from_filename(filename: str) -> str:
    """
    "nebula_life_module.py" -> "nebula_life_module"
    """
    filename = sanitize_filename(filename)
    if filename.endswith(".py"):
        filename = filename[:-3]
    filename = re.sub(r"[^a-zA-Z0-9_]+", "_", filename)
    if not filename or filename[0].isdigit():
        filename = "m_" + filename
    return filename


def parse_allow_imports(s: str) -> List[str]:
    if not s:
        return []
    out: List[str] = []
    for part in s.split(","):
        part = part.strip()
        if part:
            out.append(part)
    return out


# ---------------- Data Structures ----------------

@dataclass
class TocEntry:
    section_type: int
    flags: int
    offset: int
    size_c: int
    size_u: int
    extra_sz: int
    crc32_u: int


@dataclass
class SectionSmall:
    """
    For small sections we keep payload bytes in memory.
    For GGUF we stream using offsets.
    """
    entry: TocEntry
    extra: Dict[str, Any]
    payload_c: bytes


@dataclass
class ModuleSpec:
    filename: str
    plain_name: str
    fq_name: str
    priority: int
    enabled: bool
    source_path: str
    source: str


@dataclass
class ScriptModule:
    filename: str
    plain_name: str
    fq_name: str
    priority: int
    module: types.ModuleType


# ---------------- TOC Parsing ----------------

def find_toc_offset(path: Path, scan_back_bytes: int = 4 * 1024 * 1024) -> int:
    size = path.stat().st_size
    start = max(0, size - scan_back_bytes)
    with open(path, "rb") as f:
        f.seek(start)
        chunk = f.read(size - start)
    idx = chunk.rfind(TOC_MAGIC)
    if idx < 0:
        raise ValueError("TOC not found (TOC1). File may not be a v2 4DLLM.")
    return start + idx


def read_and_validate_toc(path: Path) -> Tuple[List[TocEntry], int]:
    toc_offset = find_toc_offset(path)
    with open(path, "rb") as f:
        f.seek(toc_offset)
        hdr = read_exact(f, TOC_HDR_STRUCT.size)
        magic, toc_ver, count = TOC_HDR_STRUCT.unpack(hdr)
        if magic != TOC_MAGIC:
            raise ValueError("Bad TOC magic")
        if toc_ver != TOC_VERSION:
            raise ValueError(f"Unsupported TOC version: {toc_ver}")

        entries_bytes = read_exact(f, TOC_ENTRY_STRUCT.size * count)
        footer_crc = struct.unpack("<I", read_exact(f, 4))[0]

        computed = crc32_bytes(hdr + entries_bytes)
        if computed != footer_crc:
            raise ValueError(f"TOC CRC mismatch: expected {footer_crc:08x}, got {computed:08x}")

        entries: List[TocEntry] = []
        for i in range(count):
            chunk = entries_bytes[i * TOC_ENTRY_STRUCT.size:(i + 1) * TOC_ENTRY_STRUCT.size]
            stype, flags, off, size_c, size_u, extra_sz, crc_u = TOC_ENTRY_STRUCT.unpack(chunk)
            entries.append(TocEntry(stype, flags, off, size_c, size_u, extra_sz, crc_u))

        return entries, toc_offset


def read_section_small(path: Path, entry: TocEntry) -> SectionSmall:
    with open(path, "rb") as f:
        f.seek(entry.offset)
        hdr = read_exact(f, SECTION_HDR_STRUCT.size)
        stype, flags, size_c, size_u, extra_sz, crc_u = SECTION_HDR_STRUCT.unpack(hdr)

        if stype != entry.section_type or flags != entry.flags:
            raise ValueError("Section header mismatch vs TOC (type/flags).")
        if size_c != entry.size_c or size_u != entry.size_u:
            raise ValueError("Section header mismatch vs TOC (sizes).")
        if extra_sz != entry.extra_sz or crc_u != entry.crc32_u:
            raise ValueError("Section header mismatch vs TOC (extra/crc).")

        extra_bytes = read_exact(f, extra_sz) if extra_sz else b"{}"
        extra = safe_json_loads(extra_bytes, default={})
        payload_c = read_exact(f, size_c) if size_c else b""
        return SectionSmall(entry=entry, extra=extra, payload_c=payload_c)


def decode_and_validate(section: SectionSmall) -> bytes:
    data = section.payload_c
    if section.entry.flags & FLAG_COMPRESSED_ZLIB:
        data = zlib.decompress(data)

    c = zlib.crc32(data) & 0xFFFFFFFF
    if c != section.entry.crc32_u:
        raise ValueError(
            f"CRC mismatch for section {section.entry.section_type:#x}: "
            f"expected {section.entry.crc32_u:08x}, got {c:08x}"
        )

    if len(data) != section.entry.size_u:
        raise ValueError(
            f"Size_u mismatch after decode: expected {section.entry.size_u}, got {len(data)}"
        )
    return data


# ---------------- GGUF Streaming Extraction ----------------

def stream_extract_gguf(fourdllm_path: Path, gguf_entry: TocEntry, out_dir: Path) -> Path:
    if gguf_entry.flags & FLAG_COMPRESSED_ZLIB:
        raise ValueError("GGUF section is compressed; runner expects GGUF raw for streaming.")

    with open(fourdllm_path, "rb") as f:
        f.seek(gguf_entry.offset)
        hdr = read_exact(f, SECTION_HDR_STRUCT.size)
        stype, flags, size_c, size_u, extra_sz, crc_u = SECTION_HDR_STRUCT.unpack(hdr)
        if stype != SECTION_GGUF_DATA:
            raise ValueError("GGUF TOC entry does not point to GGUF section.")
        if size_c != gguf_entry.size_c or size_u != gguf_entry.size_u:
            raise ValueError("GGUF header sizes mismatch vs TOC.")

        extra_bytes = read_exact(f, extra_sz) if extra_sz else b"{}"
        extra = safe_json_loads(extra_bytes, default={})
        name = sanitize_filename(str(extra.get("name") or "model.gguf"))

        out_path = out_dir / name

        crc = 0
        remaining = size_c
        chunk_sz = 1024 * 1024

        with open(out_path, "wb") as out:
            while remaining > 0:
                take = chunk_sz if remaining > chunk_sz else remaining
                chunk = read_exact(f, take)
                out.write(chunk)
                crc = zlib.crc32(chunk, crc)
                remaining -= take

        crc &= 0xFFFFFFFF
        if crc != crc_u:
            raise ValueError(f"GGUF CRC mismatch: expected {crc_u:08x}, got {crc:08x}")

        return out_path


# ---------------- Module Execution (safe/unsafe) ----------------

def make_safe_builtins(unsafe: bool) -> Dict[str, Any]:
    if unsafe:
        return dict(builtins.__dict__)

    allow = {
        "abs", "all", "any", "bool", "bytes", "callable", "chr", "dict", "enumerate", "filter",
        "float", "format", "hash", "hex", "int", "isinstance", "len", "list", "map", "max", "min",
        "print", "range", "repr", "reversed", "round", "set", "slice", "sorted", "str", "sum",
        "tuple", "zip",
        "Exception", "ValueError", "RuntimeError", "TypeError", "KeyError", "IndexError",
    }
    return {k: getattr(builtins, k) for k in allow if hasattr(builtins, k)}


def make_import_guard(allowed: List[str], unsafe: bool):
    if unsafe:
        return __import__

    allowed_set = set(a.strip() for a in allowed if a.strip())
    base_allow = {
        "__future__", "math", "re", "json", "ast", "time", "datetime",
        "random", "statistics", "collections", "typing",
    }
    allowed_set |= base_allow

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        top = name.split(".", 1)[0]
        if top not in allowed_set:
            raise ImportError(f"Import blocked: {name} (allowed: {sorted(allowed_set)})")
        return __import__(name, globals, locals, fromlist, level)

    return guarded_import


def ensure_fourdllm_package() -> None:
    """
    Ensure 'fourdllm' package exists in sys.modules so submodules can use it.
    """
    if "fourdllm" not in sys.modules:
        pkg = types.ModuleType("fourdllm")
        pkg.__path__ = []  # mark as package-like
        pkg.__package__ = "fourdllm"
        sys.modules["fourdllm"] = pkg


def detect_local_import_deps(source: str, local_plain_names: Set[str]) -> Set[str]:
    """
    Parse source for import statements referencing other injected modules.
    Returns a set of plain module names this module depends on.
    """
    deps: Set[str] = set()
    try:
        tree = ast.parse(source)
    except Exception:
        return deps

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = (alias.name or "").split(".", 1)[0]
                if top in local_plain_names:
                    deps.add(top)
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".", 1)[0]
            if mod in local_plain_names:
                deps.add(mod)
    return deps


def topo_sort_modules(specs: List[ModuleSpec]) -> List[ModuleSpec]:
    """
    Dependency-first order using a topo sort over detected local imports.
    Break ties with priority (higher first) + name.
    """
    local_names = {s.plain_name for s in specs}
    deps_map: Dict[str, Set[str]] = {s.plain_name: detect_local_import_deps(s.source, local_names) for s in specs}

    # Build reverse edges for Kahn
    incoming_count: Dict[str, int] = {n: 0 for n in local_names}
    outgoing: Dict[str, Set[str]] = {n: set() for n in local_names}

    for mod, deps in deps_map.items():
        for d in deps:
            if d == mod:
                continue
            outgoing[d].add(mod)   # d -> mod
            incoming_count[mod] += 1

    # Initial queue: no incoming deps
    def sort_key(name: str) -> Tuple[int, str]:
        s = next(x for x in specs if x.plain_name == name)
        return (-s.priority, s.plain_name)

    queue = sorted([n for n, c in incoming_count.items() if c == 0], key=sort_key)

    ordered: List[str] = []
    while queue:
        n = queue.pop(0)
        ordered.append(n)
        for m in sorted(outgoing[n], key=lambda x: x):
            incoming_count[m] -= 1
            if incoming_count[m] == 0:
                queue.append(m)
        queue.sort(key=sort_key)

    # If cycle exists, append remaining by priority
    remaining = [n for n, c in incoming_count.items() if c > 0]
    if remaining:
        remaining_sorted = sorted(remaining, key=sort_key)
        ordered.extend(remaining_sorted)

    # Map back to specs in that order
    by_name = {s.plain_name: s for s in specs}
    return [by_name[n] for n in ordered if n in by_name]


def build_module_specs(script_sections: List[SectionSmall], script_config: Dict[str, Any]) -> List[ModuleSpec]:
    cfg_map: Dict[str, Dict[str, Any]] = {}
    for s in (script_config.get("scripts") or []):
        if isinstance(s, dict) and "name" in s:
            cfg_map[str(s["name"])] = s

    specs: List[ModuleSpec] = []
    for sec in script_sections:
        extra = sec.extra or {}
        filename = sanitize_filename(str(extra.get("name") or "module.py"))
        plain = sanitize_modname_from_filename(filename)
        fq = f"fourdllm.{plain}"

        cfg = cfg_map.get(filename, {})
        enabled = bool(cfg.get("enabled", True))
        priority = int(cfg.get("priority", extra.get("priority", 0)) or 0)
        source_path = str(cfg.get("source_path", "")) if cfg else ""

        if not enabled:
            continue

        src = decode_and_validate(sec).decode("utf-8", errors="replace")

        specs.append(ModuleSpec(
            filename=filename,
            plain_name=plain,
            fq_name=fq,
            priority=priority,
            enabled=True,
            source_path=source_path,
            source=src,
        ))

    # First: sort by dependency (imports), then priority
    specs = topo_sort_modules(specs)
    return specs


def load_modules(
    specs: List[ModuleSpec],
    unsafe_modules: bool,
    allowed_imports: List[str],
) -> List[ScriptModule]:
    """
    Two-phase:
    1) Pre-register every module into sys.modules under BOTH names:
       - plain_name (e.g., nebula_life_module)
       - fq_name (e.g., fourdllm.nebula_life_module)
    2) Exec sources in dependency-first order (specs already sorted)
    """
    ensure_fourdllm_package()

    safe_bi = make_safe_builtins(unsafe_modules)
    safe_bi["__import__"] = make_import_guard(allowed_imports, unsafe_modules)

    loaded: List[ScriptModule] = []

    # Phase 1: pre-register stubs
    for s in specs:
        mod = types.ModuleType(s.fq_name)
        mod.__file__ = f"<4dllm:{s.filename}>"
        mod.__package__ = "fourdllm"
        mod.__dict__["__builtins__"] = safe_bi

        # register both names
        sys.modules[s.fq_name] = mod
        sys.modules[s.plain_name] = mod  # <-- this fixes `import nebula_life_module`

    # Phase 2: exec in order
    for s in specs:
        mod = sys.modules.get(s.fq_name)
        if mod is None:
            raise RuntimeError(f"Internal error: module stub missing for {s.fq_name}")

        ns = mod.__dict__
        ns["__name__"] = s.fq_name
        ns["__file__"] = mod.__file__

        code = compile(s.source, mod.__file__, "exec")
        exec(code, ns, ns)

        loaded.append(ScriptModule(
            filename=s.filename,
            plain_name=s.plain_name,
            fq_name=s.fq_name,
            priority=s.priority,
            module=mod,
        ))

    # Display / hooks expect priority order (highest first)
    loaded.sort(key=lambda m: (m.priority, m.plain_name), reverse=True)
    return loaded


def run_hook(mods: List[ScriptModule], hook_name: str, context: Dict[str, Any]) -> None:
    for m in mods:
        fn = m.module.__dict__.get(hook_name)
        if callable(fn):
            try:
                fn(context)
            except Exception as e:
                eprint(f"[4DLLM] Module {m.filename} hook {hook_name} error: {e}")


# ---------------- Backends ----------------

def backend_llama_cpp_available() -> bool:
    try:
        import llama_cpp  # noqa: F401
        return True
    except Exception:
        return False


class LlamaCppBackend:
    def __init__(self, gguf_path: Path, n_ctx: int, n_threads: int, n_gpu_layers: int):
        from llama_cpp import Llama  # type: ignore
        self.llm = Llama(
            model_path=str(gguf_path),
            n_ctx=n_ctx,
            n_threads=n_threads,
            n_gpu_layers=n_gpu_layers,
        )

    def complete(self, prompt: str, max_tokens: int, temperature: float) -> str:
        out = self.llm(
            prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            stop=["\nUser:", "\n### User:", "\n<|user|>"],
        )
        return (out.get("choices") or [{}])[0].get("text", "").strip()


class LlamaCliBackend:
    def __init__(self, cli_path: Path, gguf_path: Path, n_ctx: int, n_threads: int, n_gpu_layers: int):
        self.cli_path = cli_path
        self.gguf_path = gguf_path
        self.n_ctx = n_ctx
        self.n_threads = n_threads
        self.n_gpu_layers = n_gpu_layers

    def complete(self, prompt: str, max_tokens: int, temperature: float) -> str:
        cmd = [
            str(self.cli_path),
            "-m", str(self.gguf_path),
            "-n", str(max_tokens),
            "-c", str(self.n_ctx),
            "-t", str(self.n_threads),
            "--temp", str(temperature),
            "-p", prompt,
        ]
        if self.n_gpu_layers > 0:
            cmd += ["-ngl", str(self.n_gpu_layers)]

        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "llama.cpp CLI failed")

        txt = proc.stdout
        if prompt in txt:
            txt = txt.split(prompt, 1)[-1]
        return txt.strip()


# ---------------- Chat Prompt ----------------

def format_chat(history: List[Tuple[str, str]], user_msg: str) -> str:
    parts = []
    for u, a in history[-12:]:
        parts.append(f"User: {u}\nAssistant: {a}\n")
    parts.append(f"User: {user_msg}\nAssistant:")
    return "\n".join(parts)


# ---------------- Main ----------------

def main() -> int:
    ap = argparse.ArgumentParser(description="4DLLM Runner (Terminal)")
    ap.add_argument("--file", required=True, help="Path to .4dllm file")
    ap.add_argument("--backend", choices=["llama_cpp", "llama_cli"], default="llama_cpp")
    ap.add_argument("--llama-cli", default="./main", help="Path to llama.cpp CLI binary (for llama_cli backend)")
    ap.add_argument("--n-ctx", type=int, default=4096)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--gpu-layers", type=int, default=0)
    ap.add_argument("--max-tokens", type=int, default=256)
    ap.add_argument("--temp", type=float, default=0.7)

    ap.add_argument("--unsafe-modules", action="store_true",
                    help="Allow full Python builtins/imports in modules (DANGEROUS).")
    ap.add_argument("--allow-import", default="",
                    help="Comma-separated extra modules to allow importing (safe mode). Example: os,sys,pathlib")

    args = ap.parse_args()

    fourdllm_path = Path(args.file).expanduser().resolve()
    if not fourdllm_path.exists():
        eprint(f"File not found: {fourdllm_path}")
        return 2

    # Validate header
    with open(fourdllm_path, "rb") as f:
        magic = read_exact(f, 4)
        if magic != FOURDLLM_MAGIC:
            eprint("Not a 4DLLM file (bad magic).")
            return 2
        ver = struct.unpack("<I", read_exact(f, 4))[0]
        if ver != FOURDLLM_VERSION_EXPECTED:
            eprint(f"Unsupported 4DLLM version: {ver} (expected {FOURDLLM_VERSION_EXPECTED})")
            return 2

    entries, toc_off = read_and_validate_toc(fourdllm_path)

    gguf_entries = [e for e in entries if e.section_type == SECTION_GGUF_DATA]
    if not gguf_entries:
        eprint("[4DLLM] No GGUF section found.")
        return 2
    gguf_entry = gguf_entries[0]

    metadata: Dict[str, Any] = {}
    script_config: Dict[str, Any] = {}
    script_sections: List[SectionSmall] = []

    for ent in entries:
        if ent.section_type == SECTION_METADATA:
            sec = read_section_small(fourdllm_path, ent)
            metadata = safe_json_loads(decode_and_validate(sec), default={})
        elif ent.section_type == SECTION_SCRIPT_CONFIG:
            sec = read_section_small(fourdllm_path, ent)
            script_config = safe_json_loads(decode_and_validate(sec), default={})
        elif ent.section_type == SECTION_PYTHON_SCRIPT:
            script_sections.append(read_section_small(fourdllm_path, ent))

    allowed_imports = parse_allow_imports(args.allow_import)

    specs = build_module_specs(script_sections, script_config)
    modules = load_modules(specs, args.unsafe_modules, allowed_imports)

    print("\n[4DLLM] Loaded:")
    print(f"  file: {fourdllm_path.name}")
    print(f"  toc_offset: {toc_off}")
    print(f"  modules: {len(modules)}")
    for m in modules[:30]:
        print(f"    - {m.filename} (priority={m.priority})  as {m.plain_name} / {m.fq_name}")
    if len(modules) > 30:
        print(f"    ... +{len(modules)-30} more")

    with tempfile.TemporaryDirectory(prefix="4dllm_run_") as td:
        temp_dir = Path(td)
        gguf_path = stream_extract_gguf(fourdllm_path, gguf_entry, temp_dir)

        if args.backend == "llama_cpp":
            if not backend_llama_cpp_available():
                eprint("[4DLLM] llama-cpp-python not installed. Use --backend llama_cli or install llama-cpp-python.")
                return 3
            backend = LlamaCppBackend(gguf_path, args.n_ctx, args.threads, args.gpu_layers)
        else:
            cli = Path(args.llama_cli).expanduser().resolve()
            if not cli.exists():
                eprint(f"[4DLLM] llama.cpp CLI not found: {cli}")
                return 3
            backend = LlamaCliBackend(cli, gguf_path, args.n_ctx, args.threads, args.gpu_layers)

        history: List[Tuple[str, str]] = []
        print("\n[4DLLM] Chat ready. Type /exit to quit. /mods to list modules.\n")

        while True:
            try:
                user_msg = input("You> ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\n[4DLLM] Bye.")
                return 0

            if not user_msg:
                continue
            if user_msg.lower() in ("/exit", "/quit"):
                print("[4DLLM] Bye.")
                return 0
            if user_msg.lower() in ("/mods", "/modules"):
                print("[4DLLM] Modules:")
                for m in modules:
                    print(f"  - {m.filename} (priority={m.priority})")
                continue

            context: Dict[str, Any] = {
                "input": user_msg,
                "output": None,
                "meta": {
                    "time": time.time(),
                    "metadata": metadata,
                    "script_config": script_config,
                },
                "state": {},
                "tools": {},
            }

            run_hook(modules, "pre_prompt", context)
            run_hook(modules, "run", context)  # legacy optional hook

            prompt = format_chat(history, str(context.get("input", user_msg)))

            try:
                reply = backend.complete(prompt, max_tokens=args.max_tokens, temperature=args.temp)
            except Exception as e:
                eprint(f"[4DLLM] Backend error: {e}")
                continue

            context["output"] = reply

            run_hook(modules, "post_output", context)
            run_hook(modules, "post_prompt", context)

            final_reply = str(context.get("output", reply))
            print(f"AI> {final_reply}\n")

            history.append((user_msg, final_reply))


if __name__ == "__main__":
    raise SystemExit(main())

