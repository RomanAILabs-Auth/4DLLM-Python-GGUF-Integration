# 4DLLM Studio (RomanAILabs)

**4DLLM** is a single-file container format + toolchain for local LLMs: it packages **GGUF model bytes (weights)** alongside **metadata, config, and optional Python modules/scripts** into one `.4dllm` file that you can **build, inspect, validate, train, and run** with safe-by-default controls.

## Screenshots

### Run 4DLLM Model
![4DLLM Studio - Run Screen](https://github.com/RomanAILabs-Auth/4DLLM-Python-GGUF-Integration/blob/main/run.png?raw=true)

### Train 4DLLM Model
![4DLLM Studio - Train Screen](assets/screenshots/train.png)

---

## What’s in this repo / zip
- `4dllm_builder_v2.0.py` — GUI builder to create `.4dllm` packages (streams GGUF; does not load whole model into RAM)
- `4dllm_builder.py` — builder (legacy/alternate)
- `4dllm_runner.py` — terminal runner (CLI)
- `4dllm_runner_gui.py` — desktop GUI runner (Tk/CustomTkinter)
- `4dllm_runner_gui_qt.py` — PyQt6 + WebEngine runner GUI (HTML/CSS UI)
- `4dllm-antivirus.py` — GUI scanner for embedded modules/scripts (flags risky imports/calls)
- `gguf-editor.py` — GGUF metadata editor GUI (with optional enhanced backend)

## .4dllm file format (high level)
A `.4dllm` contains:
- a small header (`4DLL` + version),
- a sequence of typed sections (GGUF, scripts, metadata, config, etc.),
- a footer **TOC** that records section offsets/sizes and integrity checks so tools can quickly inspect/verify contents.

## Quick Start

### 1) Build a .4dllm (GUI)
~~~bash
python3 4dllm_builder_v2.0.py
~~~
- Select a `.gguf`
- Add/enable scripts/modules (optional)
- Build → outputs a `.4dllm`

### 2) Run a .4dllm (Terminal)
~~~bash
python3 4dllm_runner.py --file /path/to/model.4dllm --backend llama_cpp --threads 4 --n-ctx 4096 --max-tokens 256 --temp 0.7
~~~

**Safe vs Unsafe modules**
- Safe (default): restricted imports
- Unsafe (dangerous): allows full module imports/builtins
~~~bash
python3 4dllm_runner.py --file /path/to/model.4dllm --unsafe-modules
~~~

Allow a few extra imports while staying in safe mode:
~~~bash
python3 4dllm_runner.py --file /path/to/model.4dllm --allow-import "hashlib,pathlib"
~~~

### 3) Run + Inspect via GUI (Tk/CustomTkinter)
~~~bash
python3 4dllm_runner_gui.py
~~~
- Run tab: select `.4dllm`, run/stop, copy command, view output
- Inspect tab: view package structure/sections
- Scripts tab: view/enable/disable embedded scripts (if provided)
- Settings: profiles and safety toggles (depending on your build)

### 4) Run via Qt GUI (PyQt6 + WebEngine)
~~~bash
python3 4dllm_runner_gui_qt.py
~~~
Optional deps (Linux/macOS/Windows):
~~~bash
pip install PyQt6 PyQt6-WebEngine
~~~

## Security Notes
- **Safe mode** is the default: embedded scripts/modules should be treated as untrusted.
- Only enable **unsafe modules** if you trust the `.4dllm` contents.
- Use `4dllm-antivirus.py` to scan packages before running modules.

## GGUF Metadata Editor
~~~bash
python3 gguf-editor.py
~~~
- Edits GGUF metadata (not training weights)
- If an enhanced backend (`citadel_fusion_editor`) is available, it will use it; otherwise it runs in fallback mode.

## Troubleshooting
- If output “hangs” in the GUI: confirm the runner process is still alive and stdout is being read/flushed.
- If an import is blocked in safe mode: either add it to `--allow-import` or run with `--unsafe-modules` (only if trusted).
- If the GUI looks “off”: verify you’re running the correct file from the correct folder (common gotcha).

---

Copyright Daniel Harding - RomanAILabs  
Credits: OpenAI GPT-5.2 Thinking
