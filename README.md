#Copyright Daniel Harding - RomanAILabs

# 4DLLM-Python-GGUF-Integration
A runtime and builder enabling direct Python execution inside GGUF-based LLMs using the 4DLLM container format. Supports modular cognition, dependency-aware module loading, and programmable model behavior at inference time.

# 4DLLM-Python / GGUF-Integration

## Overview

This project implements a **custom runtime and builder** that enables **direct Python execution inside GGUF-based large language models** using the **4DLLM container format**.

It allows LLMs to be extended at inference time with **modular Python cognition**, including math engines, reasoning systems, state management, and external tooling — without retraining model weights.

---

## What This Does

- Packages a GGUF model together with Python modules into a single `.4dllm` file
- Executes Python modules **inside the model runtime lifecycle**
- Supports dependency-aware module loading and cross-module imports
- Enables programmable behavior via inference hooks (pre-prompt, post-output, etc.)
- Streams large GGUF files safely without loading them fully into memory

This separates **static intelligence (weights)** from **dynamic cognition (code)**.

---

## Core Components

### 1) 4DLLM Builder
- Creates `.4dllm` files from:
  - A GGUF model
  - Metadata
  - Python scripts
  - Script configuration
- Validates and packages all components into a single portable container

### 2) 4DLLM Runner
- Extracts and runs GGUF models from `.4dllm`
- Loads Python modules as real runtime modules
- Resolves module dependencies automatically
- Executes Python hooks around model inference
- Supports both `llama-cpp-python` and `llama.cpp` CLI backends

---

## ⚠️ Required Project Structure

**A scripts folder is mandatory.**

The builder expects a dedicated folder for Python modules. Modules must be placed in this folder to be discovered and packaged.

### Required layout

project_root/
├── 4dllm_builder.py
├── 4dllm_runner.py
├── modules/
│ ├── module_one.py
│ ├── module_two.py
│ └── ...


### Rules

- Folder name **must be `modules` (lowercase)**
- Every `*.py` file inside `modules/` is treated as an injectable runtime module
- Modules may import each other by filename (e.g. `import nebula_life_module`)
- Module execution order is resolved automatically based on dependencies when running

---

## Module Hooks

Each module may optionally define any of the following hooks:

- `pre_prompt(context)`
- `run(context)`
- `post_output(context)`
- `post_prompt(context)`

Modules receive a shared `context` object containing:

- `input`: user input text
- `output`: model output text (after inference)
- `meta`: runtime metadata (including builder metadata + script_config)
- `state`: persistent dictionary for module state (future expansion)
- `tools`: tool registry dictionary (future expansion)

---

## Safety Modes

- **Safe mode** (default): restricted imports and builtins
- **Unsafe mode** (`--unsafe-modules`): full Python access  
  (required for heavy stacks like NumPy, Flask, Qiskit)

---

## Why This Exists

Traditional LLMs treat model weights as the sole source of intelligence.

This project introduces a programmable cognition layer that allows:

- deterministic math
- symbolic reasoning
- stateful memory
- external systems
- domain-specific logic

…to run inside the model runtime itself, without retraining weights.

---

## Status

- ✅ Builder functional
- ✅ Runner functional
- ✅ Python module injection working
- ✅ Dependency resolution working
- ✅ GGUF streaming extraction working

This is a working v1 platform.

---

## License

Copyright Daniel Harding - RomanAILabs  
All rights reserved unless otherwise stated.


# 1) Run a 4DLLM container (.4dllm) with llama-cpp-python (recommended)
cd ~/Documents/FusionTrainer && python3 4dllm_runner.py --file ~/Desktop/prototype.4dllm --backend llama_cpp --threads 4 --n-ctx 4096 --max-tokens 256 --temp 0.7 --unsafe-modules

# 2) Run a GGUF directly with llama-cpp-python (no 4DLLM)
python3 -c "from llama_cpp import Llama; llm=Llama(model_path='/path/to/model.gguf', n_ctx=4096, n_threads=4, n_gpu_layers=0); print(llm('User: Hello\\nAssistant:', max_tokens=128, temperature=0.7)['choices'][0]['text'])"

# 3) Run a GGUF directly with llama.cpp CLI (main)
#/path/to/main -m /path/to/model.gguf -c 4096 -t 4 -n 128 --temp 0.7 -p "User: Hello\nAssistant:"
/path/to/main -m /path/to/model.gguf -c 4096 -t 4 -n 128 --temp 0.7 -p $'User: Hello\nAssistant:'
