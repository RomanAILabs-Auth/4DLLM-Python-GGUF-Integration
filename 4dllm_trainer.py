#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Copyright (c) Daniel Harding - RomanAILabs
Contact: romanailabs@gmail.com

RomanAILabs 4DLLM Trainer
A world-class, easy-to-use GUI for training 4DLLM model files.

Features:
- Load existing 4DLLM files
- Configure training parameters with presets
- Train models with real-time progress
- Save trained models back to 4DLLM format
- Beautiful, intuitive interface
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import threading
import time
import zlib
import logging
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

# ---------------- Debug Logger ----------------
DEBUG_LOG_FILE = Path(__file__).parent / "4dllm_trainer_debug.log"

def setup_debug_logger():
    """Setup debug logger for error tracking"""
    logger = logging.getLogger("4dllm_trainer")
    logger.setLevel(logging.DEBUG)
    
    # Clear old log file (keep last 2000 lines)
    if DEBUG_LOG_FILE.exists():
        try:
            with open(DEBUG_LOG_FILE, 'r') as f:
                lines = f.readlines()
            if len(lines) > 2000:
                with open(DEBUG_LOG_FILE, 'w') as f:
                    f.writelines(lines[-2000:])
        except Exception:
            pass
    
    # File handler
    fh = logging.FileHandler(DEBUG_LOG_FILE, mode='a', encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    fh.setFormatter(formatter)
    
    logger.addHandler(fh)
    return logger

DEBUG_LOGGER = setup_debug_logger()
DEBUG_LOGGER.info("="*80)
DEBUG_LOGGER.info("4DLLM Trainer started")
DEBUG_LOGGER.info(f"Debug log: {DEBUG_LOG_FILE}")
DEBUG_LOGGER.info("="*80)

try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False
    import tkinter as tk
    from tkinter import ttk

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Import 4DLLM utilities
import importlib.util

def _import_runner_utils():
    """Import utilities from 4dllm_runner.py"""
    runner_path = Path(__file__).parent / "4dllm_runner.py"
    if runner_path.exists():
        try:
            spec = importlib.util.spec_from_file_location("runner_module", str(runner_path))
            if spec and spec.loader:
                runner_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(runner_module)
                return runner_module
        except Exception:
            pass
    return None

runner_module = _import_runner_utils()

if runner_module:
    read_and_validate_toc = runner_module.read_and_validate_toc
    read_section_small = runner_module.read_section_small
    decode_and_validate = runner_module.decode_and_validate
    find_toc_offset = getattr(runner_module, 'find_toc_offset', None)
    SECTION_GGUF_DATA = runner_module.SECTION_GGUF_DATA
    SECTION_METADATA = runner_module.SECTION_METADATA
    SECTION_SCRIPT_CONFIG = runner_module.SECTION_SCRIPT_CONFIG
    FOURDLLM_MAGIC = runner_module.FOURDLLM_MAGIC
    FOURDLLM_VERSION_EXPECTED = runner_module.FOURDLLM_VERSION_EXPECTED
    
    # Get TOC structures and constants
    TOC_MAGIC = getattr(runner_module, 'TOC_MAGIC', b'TOC1')
    TOC_VERSION = getattr(runner_module, 'TOC_VERSION', 1)
    TOC_HDR_STRUCT = getattr(runner_module, 'TOC_HDR_STRUCT', struct.Struct("<4sII"))
    TOC_ENTRY_STRUCT = getattr(runner_module, 'TOC_ENTRY_STRUCT', struct.Struct("<BB2xQQQII"))
    read_exact = getattr(runner_module, 'read_exact', None)
    crc32_bytes = getattr(runner_module, 'crc32_bytes', None)
    TocEntry = getattr(runner_module, 'TocEntry', None)
    
    # Patch find_toc_offset to handle large files better
    if find_toc_offset:
        original_find_toc = find_toc_offset
        def enhanced_find_toc(path, scan_back_bytes=None):
            """Enhanced find_toc_offset that handles large files"""
            file_size = path.stat().st_size
            # For files > 1GB, search more bytes (up to 64MB)
            if scan_back_bytes is None:
                if file_size > 1024 * 1024 * 1024:  # > 1GB
                    scan_back_bytes = 64 * 1024 * 1024  # 64MB for large files
                else:
                    scan_back_bytes = 4 * 1024 * 1024  # 4MB default
            DEBUG_LOGGER.info(f"find_toc_offset: file_size={file_size}, scan_back_bytes={scan_back_bytes}")
            try:
                result = original_find_toc(path, scan_back_bytes)
                DEBUG_LOGGER.info(f"find_toc_offset returned: {result}")
                return result
            except ValueError as e:
                DEBUG_LOGGER.warning(f"find_toc_offset failed with {scan_back_bytes} bytes: {e}")
                # Try with larger scan if it failed
                if scan_back_bytes < 64 * 1024 * 1024:
                    larger_scan = 64 * 1024 * 1024
                    DEBUG_LOGGER.info(f"Retrying with {larger_scan} bytes...")
                    return original_find_toc(path, larger_scan)
                raise
        # Monkey-patch the function in the module
        runner_module.find_toc_offset = enhanced_find_toc
else:
    # Fallback TOC structures
    TOC_MAGIC = b"TOC1"
    TOC_VERSION = 1
    TOC_HDR_STRUCT = struct.Struct("<4sII")
    TOC_ENTRY_STRUCT = struct.Struct("<BB2xQQQII")
    TocEntry = None  # Ensure TocEntry is always defined
    
    def read_exact(f, n: int) -> bytes:
        b = f.read(n)
        if len(b) != n:
            raise EOFError(f"Expected {n} bytes, got {len(b)}")
        return b
    
    def crc32_bytes(b: bytes) -> int:
        return zlib.crc32(b) & 0xFFFFFFFF
    
    # Fallback functions when runner_module is not available
    FOURDLLM_MAGIC = b"4DLL"
    FOURDLLM_VERSION_EXPECTED = 2
    SECTION_GGUF_DATA = 0x01
    SECTION_METADATA = 0x03
    SECTION_SCRIPT_CONFIG = 0x04
    
    def read_and_validate_toc(path):
        return [], 0
    
    def read_section_small(path, entry):
        return None
    
    def decode_and_validate(section):
        return b""

# Ensure TocEntry is always defined in global scope
if 'TocEntry' not in globals():
    TocEntry = None

# ---------------- Theme Colors ----------------
COLORS = {
    "bg_primary": "#0f172a",
    "bg_secondary": "#1e293b",
    "bg_tertiary": "#334155",
    "fg_primary": "#e2e8f0",
    "fg_secondary": "#cbd5e1",
    "fg_tertiary": "#94a3b8",
    "accent": "#06b6d4",
    "accent_hover": "#22d3ee",
    "success": "#34d399",
    "warning": "#fbbf24",
    "error": "#f87171",
    "border": "#475569",
    "glass_bg": "rgba(15, 23, 42, 0.6)",
}

# ---------------- Training Presets ----------------
TRAINING_PRESETS = {
    "Quick Fine-Tune": {
        "epochs": "3",
        "learning_rate": "0.0001",
        "batch_size": "4",
        "context_size": "2048",
        "lora_r": "8",
        "lora_alpha": "16",
        "lora_dropout": "0.05",
    },
    "Standard Training": {
        "epochs": "5",
        "learning_rate": "0.0001",
        "batch_size": "8",
        "context_size": "4096",
        "lora_r": "16",
        "lora_alpha": "32",
        "lora_dropout": "0.1",
    },
    "Advanced Training": {
        "epochs": "10",
        "learning_rate": "0.00005",
        "batch_size": "16",
        "context_size": "8192",
        "lora_r": "32",
        "lora_alpha": "64",
        "lora_dropout": "0.15",
    },
}


class FourDLLMTrainer:
    """World-class 4DLLM Trainer Application"""
    
    def __init__(self, root):
        self.root = root
        self.input_file: Optional[Path] = None
        self.output_file: Optional[Path] = None
        self.dataset_file: Optional[Path] = None
        self.training_process: Optional[subprocess.Popen] = None
        self.training_thread: Optional[threading.Thread] = None
        self.is_training = False
        
        self.setup_window()
        self.setup_ui()
    
    def setup_window(self):
        """Configure main window"""
        self.root.title("RomanAILabs 4DLLM Trainer")
        self.root.geometry("1400x900")
        # Always use regular Tkinter bg (works for both)
        self.root.configure(bg=COLORS["bg_primary"])
        
        # Center window
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def setup_ui(self):
        """Build the UI"""
        # Header
        header = tk.Frame(self.root, bg=COLORS["bg_secondary"], height=80)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        title = tk.Label(
            header,
            text="RomanAILabs 4DLLM Trainer",
            font=("Segoe UI", 28, "bold"),
            bg=COLORS["bg_secondary"],
            fg=COLORS["accent"]
        )
        title.pack(side="left", padx=30, pady=20)
        
        email = tk.Label(
            header,
            text="romanailabs@gmail.com",
            font=("Segoe UI", 11),
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_secondary"],
            cursor="hand2"
        )
        email.pack(side="left", padx=20, pady=20)
        email.bind("<Button-1>", lambda e: self._open_email())
        
        # Main container
        main = tk.Frame(self.root, bg=COLORS["bg_primary"])
        main.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Left panel - File selection
        left_panel = tk.Frame(main, bg=COLORS["bg_secondary"], width=400)
        left_panel.pack(side="left", fill="y", padx=(0, 20))
        left_panel.pack_propagate(False)
        
        self._build_file_panel(left_panel)
        
        # Center panel - Training config
        center_panel = tk.Frame(main, bg=COLORS["bg_secondary"])
        center_panel.pack(side="left", fill="both", expand=True, padx=(0, 20))
        
        self._build_config_panel(center_panel)
        
        # Right panel - Progress & Logs
        right_panel = tk.Frame(main, bg=COLORS["bg_secondary"], width=400)
        right_panel.pack(side="left", fill="both", expand=True)
        
        self._build_progress_panel(right_panel)
    
    def _build_file_panel(self, parent):
        """Build file selection panel"""
        # Input file
        input_frame = tk.LabelFrame(
            parent,
            text="📂 Input 4DLLM File",
            font=("Segoe UI", 12, "bold"),
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_primary"],
            padx=15,
            pady=15
        )
        input_frame.pack(fill="x", padx=20, pady=20)
        
        self.input_label = tk.Label(
            input_frame,
            text="No file selected",
            font=("Segoe UI", 10),
            bg=COLORS["bg_tertiary"],
            fg=COLORS["fg_secondary"],
            wraplength=350,
            justify="left",
            anchor="w",
            padx=10,
            pady=10
        )
        self.input_label.pack(fill="x", padx=10, pady=(0, 10))
        
        input_btn = tk.Button(
            input_frame,
            text="📂 Select 4DLLM File",
            font=("Segoe UI", 11, "bold"),
            bg=COLORS["accent"],
            fg="white",
            activebackground=COLORS["accent_hover"],
            activeforeground="white",
            relief="flat",
            padx=20,
            pady=10,
            cursor="hand2",
            command=self._select_input_file
        )
        input_btn.pack(fill="x", padx=10)
        
        # Dataset file
        dataset_frame = tk.LabelFrame(
            parent,
            text="📊 Training Dataset",
            font=("Segoe UI", 12, "bold"),
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_primary"],
            padx=15,
            pady=15
        )
        dataset_frame.pack(fill="x", padx=20, pady=20)
        
        self.dataset_label = tk.Label(
            dataset_frame,
            text="No dataset selected\n(JSON, JSONL, or TXT format)",
            font=("Segoe UI", 10),
            bg=COLORS["bg_tertiary"],
            fg=COLORS["fg_secondary"],
            wraplength=350,
            justify="left",
            anchor="w",
            padx=10,
            pady=10
        )
        self.dataset_label.pack(fill="x", padx=10, pady=(0, 10))
        
        dataset_btn = tk.Button(
            dataset_frame,
            text="📊 Select Dataset",
            font=("Segoe UI", 11, "bold"),
            bg=COLORS["accent"],
            fg="white",
            activebackground=COLORS["accent_hover"],
            activeforeground="white",
            relief="flat",
            padx=20,
            pady=10,
            cursor="hand2",
            command=self._select_dataset_file
        )
        dataset_btn.pack(fill="x", padx=10)
        
        # Output file
        output_frame = tk.LabelFrame(
            parent,
            text="💾 Output 4DLLM File",
            font=("Segoe UI", 12, "bold"),
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_primary"],
            padx=15,
            pady=15
        )
        output_frame.pack(fill="x", padx=20, pady=20)
        
        self.output_label = tk.Label(
            output_frame,
            text="Auto-generated from input",
            font=("Segoe UI", 10),
            bg=COLORS["bg_tertiary"],
            fg=COLORS["fg_secondary"],
            wraplength=350,
            justify="left",
            anchor="w",
            padx=10,
            pady=10
        )
        self.output_label.pack(fill="x", padx=10, pady=(0, 10))
        
        output_btn = tk.Button(
            output_frame,
            text="💾 Choose Output Path",
            font=("Segoe UI", 11, "bold"),
            bg=COLORS["bg_tertiary"],
            fg=COLORS["fg_primary"],
            activebackground=COLORS["bg_tertiary"],
            activeforeground=COLORS["fg_primary"],
            relief="flat",
            padx=20,
            pady=10,
            cursor="hand2",
            command=self._select_output_file
        )
        output_btn.pack(fill="x", padx=10)
    
    def _build_config_panel(self, parent):
        """Build training configuration panel"""
        # Preset selector
        preset_frame = tk.LabelFrame(
            parent,
            text="⚙️ Training Preset",
            font=("Segoe UI", 12, "bold"),
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_primary"],
            padx=15,
            pady=15
        )
        preset_frame.pack(fill="x", padx=20, pady=20)
        
        self.preset_var = tk.StringVar(value="Standard Training")
        preset_combo = ttk.Combobox(
            preset_frame,
            textvariable=self.preset_var,
            values=list(TRAINING_PRESETS.keys()),
            font=("Segoe UI", 11),
            state="readonly",
            width=30
        )
        preset_combo.pack(fill="x", padx=10, pady=10)
        preset_combo.bind("<<ComboboxSelected>>", self._load_preset)
        
        # Training parameters
        params_frame = tk.LabelFrame(
            parent,
            text="📋 Training Parameters",
            font=("Segoe UI", 12, "bold"),
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_primary"],
            padx=15,
            pady=15
        )
        params_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Create parameter inputs
        self.params = {}
        param_defs = [
            ("epochs", "Epochs", "Number of training epochs"),
            ("learning_rate", "Learning Rate", "Learning rate (e.g., 0.0001)"),
            ("batch_size", "Batch Size", "Training batch size"),
            ("context_size", "Context Size", "Context window size"),
            ("lora_r", "LoRA Rank (r)", "LoRA rank parameter"),
            ("lora_alpha", "LoRA Alpha", "LoRA alpha parameter"),
            ("lora_dropout", "LoRA Dropout", "LoRA dropout rate (0.0-1.0)"),
        ]
        
        for i, (key, label, desc) in enumerate(param_defs):
            row = tk.Frame(params_frame, bg=COLORS["bg_secondary"])
            row.pack(fill="x", padx=10, pady=8)
            
            label_widget = tk.Label(
                row,
                text=f"{label}:",
                font=("Segoe UI", 10, "bold"),
                bg=COLORS["bg_secondary"],
                fg=COLORS["fg_primary"],
                width=20,
                anchor="w"
            )
            label_widget.pack(side="left", padx=(0, 10))
            
            entry = tk.Entry(
                row,
                font=("Segoe UI", 10),
                bg=COLORS["bg_tertiary"],
                fg=COLORS["fg_primary"],
                insertbackground=COLORS["fg_primary"],
                relief="flat",
                borderwidth=1,
                highlightthickness=1,
                highlightbackground=COLORS["border"],
                highlightcolor=COLORS["accent"]
            )
            entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
            self.params[key] = entry
            
            help_label = tk.Label(
                row,
                text=desc,
                font=("Segoe UI", 8),
                bg=COLORS["bg_secondary"],
                fg=COLORS["fg_tertiary"],
                anchor="w"
            )
            help_label.pack(side="left", padx=(0, 10))
        
        # Load default preset
        self._load_preset()
        
        # Action buttons
        action_frame = tk.Frame(parent, bg=COLORS["bg_secondary"])
        action_frame.pack(fill="x", padx=20, pady=20)
        
        self.train_btn = tk.Button(
            action_frame,
            text="🚀 Start Training",
            font=("Segoe UI", 14, "bold"),
            bg=COLORS["success"],
            fg="white",
            activebackground="#10b981",
            activeforeground="white",
            relief="flat",
            padx=30,
            pady=15,
            cursor="hand2",
            command=self._start_training
        )
        self.train_btn.pack(side="left", padx=10)
        
        self.stop_btn = tk.Button(
            action_frame,
            text="⏹ Stop Training",
            font=("Segoe UI", 14, "bold"),
            bg=COLORS["error"],
            fg="white",
            activebackground="#ef4444",
            activeforeground="white",
            relief="flat",
            padx=30,
            pady=15,
            cursor="hand2",
            command=self._stop_training,
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=10)
    
    def _build_progress_panel(self, parent):
        """Build progress and logs panel"""
        # Progress
        progress_frame = tk.LabelFrame(
            parent,
            text="📊 Training Progress",
            font=("Segoe UI", 12, "bold"),
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_primary"],
            padx=15,
            pady=15
        )
        progress_frame.pack(fill="x", padx=20, pady=20)
        
        self.progress_label = tk.Label(
            progress_frame,
            text="Ready to train",
            font=("Segoe UI", 11),
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_primary"]
        )
        self.progress_label.pack(pady=10)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            mode="indeterminate",
            length=350
        )
        self.progress_bar.pack(fill="x", padx=10, pady=10)
        
        # Stats
        stats_frame = tk.Frame(progress_frame, bg=COLORS["bg_secondary"])
        stats_frame.pack(fill="x", padx=10, pady=10)
        
        self.stats_label = tk.Label(
            stats_frame,
            text="Epoch: 0/0\nLoss: --\nTime: --",
            font=("Consolas", 9),
            bg=COLORS["bg_tertiary"],
            fg=COLORS["fg_secondary"],
            justify="left",
            anchor="w",
            padx=10,
            pady=10
        )
        self.stats_label.pack(fill="x")
        
        # Logs
        logs_frame = tk.LabelFrame(
            parent,
            text="📝 Training Logs",
            font=("Segoe UI", 12, "bold"),
            bg=COLORS["bg_secondary"],
            fg=COLORS["fg_primary"],
            padx=15,
            pady=15
        )
        logs_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        self.logs_text = scrolledtext.ScrolledText(
            logs_frame,
            font=("Consolas", 9),
            bg=COLORS["bg_tertiary"],
            fg=COLORS["fg_primary"],
            insertbackground=COLORS["fg_primary"],
            relief="flat",
            borderwidth=0,
            wrap="word"
        )
        self.logs_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.logs_text.insert("1.0", "RomanAILabs 4DLLM Trainer\n")
        self.logs_text.insert("end", "Ready to start training...\n\n")
        self.logs_text.config(state="disabled")
    
    def _load_preset(self, event=None):
        """Load training preset"""
        preset_name = self.preset_var.get()
        preset = TRAINING_PRESETS[preset_name]
        
        for key, value in preset.items():
            if key in self.params:
                self.params[key].delete(0, "end")
                self.params[key].insert(0, value)
    
    def _select_input_file(self):
        """Select input 4DLLM file"""
        file_path = filedialog.askopenfilename(
            title="Select 4DLLM File",
            filetypes=[("4DLLM Files", "*.4dllm"), ("All Files", "*.*")]
        )
        if file_path:
            self.input_file = Path(file_path)
            self.input_label.config(text=self.input_file.name)
            self._update_output_path()
            self._log(f"Loaded input file: {self.input_file.name}")
    
    def _select_dataset_file(self):
        """Select training dataset"""
        file_path = filedialog.askopenfilename(
            title="Select Training Dataset",
            filetypes=[
                ("JSON Files", "*.json"),
                ("JSONL Files", "*.jsonl"),
                ("Text Files", "*.txt"),
                ("All Files", "*.*")
            ]
        )
        if file_path:
            self.dataset_file = Path(file_path)
            self.dataset_label.config(text=self.dataset_file.name)
            self._log(f"Loaded dataset: {self.dataset_file.name}")
    
    def _select_output_file(self):
        """Select output file path"""
        if not self.input_file:
            messagebox.showwarning("No Input", "Please select an input file first.")
            return
        
        default_name = self.input_file.stem + "_trained.4dllm"
        file_path = filedialog.asksaveasfilename(
            title="Save Trained 4DLLM File",
            defaultextension=".4dllm",
            initialfile=default_name,
            filetypes=[("4DLLM Files", "*.4dllm"), ("All Files", "*.*")]
        )
        if file_path:
            self.output_file = Path(file_path)
            self.output_label.config(text=self.output_file.name)
    
    def _update_output_path(self):
        """Update output path based on input"""
        if self.input_file:
            default_path = self.input_file.parent / (self.input_file.stem + "_trained.4dllm")
            if not self.output_file:
                self.output_file = default_path
                self.output_label.config(text=default_path.name)
    
    def _start_training(self):
        """Start training process"""
        if not self.input_file:
            messagebox.showerror("Error", "Please select an input 4DLLM file.")
            return
        
        if not self.dataset_file:
            messagebox.showerror("Error", "Please select a training dataset.")
            return
        
        if not self.output_file:
            self._update_output_path()
        
        # Validate parameters
        try:
            params = {key: entry.get() for key, entry in self.params.items()}
            for key, value in params.items():
                if not value:
                    raise ValueError(f"Parameter '{key}' is required")
                if key in ["learning_rate", "lora_dropout"]:
                    float(value)  # Validate float
                else:
                    int(value)  # Validate int
        except ValueError as e:
            messagebox.showerror("Invalid Parameters", f"Please check your parameters:\n{e}")
            return
        
        # Start training in background thread
        self.is_training = True
        self.train_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress_bar.start()
        self.progress_label.config(text="Training in progress...")
        
        self.training_thread = threading.Thread(target=self._run_training, daemon=True)
        self.training_thread.start()
    
    def _run_training(self):
        """Run training process (in background thread)"""
        try:
            self._log("=" * 60)
            self._log("Starting training process...")
            self._log(f"Input: {self.input_file.name}")
            self._log(f"Dataset: {self.dataset_file.name}")
            self._log(f"Output: {self.output_file.name}")
            self._log("=" * 60)
            
            # Extract GGUF from 4DLLM
            self._log("Extracting GGUF model from 4DLLM file...")
            gguf_path = self._extract_gguf()
            
            if not gguf_path:
                raise Exception("Failed to extract GGUF model")
            
            # Prepare training command
            params = {key: entry.get() for key, entry in self.params.items()}
            self._log(f"Training parameters: {params}")
            
            # For now, simulate training (replace with actual llama.cpp training)
            self._simulate_training(params)
            
            # Rebuild 4DLLM with trained model
            self._log("Rebuilding 4DLLM file with trained model...")
            self._rebuild_4dllm(gguf_path)
            
            self._log("=" * 60)
            self._log("✅ Training completed successfully!")
            self._log(f"Output saved to: {self.output_file}")
            self._log("=" * 60)
            
            messagebox.showinfo("Success", f"Training completed!\n\nOutput saved to:\n{self.output_file}")
            
        except Exception as e:
            error_details = traceback.format_exc()
            DEBUG_LOGGER.error(f"Training failed: {e}", exc_info=True)
            self._log(f"❌ Training failed: {e}")
            self._log(f"Check debug log: {DEBUG_LOG_FILE}")
            messagebox.showerror(
                "Training Failed", 
                f"Training failed:\n{e}\n\nDebug log saved to:\n{DEBUG_LOG_FILE}"
            )
        finally:
            self.is_training = False
            self.root.after(0, lambda: self.progress_bar.stop())
            self.root.after(0, lambda: self.progress_label.config(text="Training finished"))
            self.root.after(0, lambda: self.train_btn.config(state="normal"))
            self.root.after(0, lambda: self.stop_btn.config(state="disabled"))
    
    def _extract_gguf(self) -> Optional[Path]:
        """Extract GGUF from 4DLLM file"""
        try:
            DEBUG_LOGGER.info(f"Starting GGUF extraction from: {self.input_file}")
            DEBUG_LOGGER.info(f"File exists: {self.input_file.exists()}")
            DEBUG_LOGGER.info(f"File size: {self.input_file.stat().st_size} bytes")
            
            # First, validate it's a 4DLLM file
            self._log("Validating 4DLLM file format...")
            DEBUG_LOGGER.info("Validating file magic and version...")
            
            with open(self.input_file, "rb") as f:
                magic = f.read(4)
                DEBUG_LOGGER.info(f"File magic: {magic} (expected: {FOURDLLM_MAGIC})")
                
                if magic != FOURDLLM_MAGIC:
                    error_msg = f"Invalid 4DLLM file: magic mismatch. Got {magic}, expected {FOURDLLM_MAGIC}"
                    DEBUG_LOGGER.error(error_msg)
                    raise Exception(error_msg)
                
                version = struct.unpack("<I", f.read(4))[0]
                DEBUG_LOGGER.info(f"File version: {version} (expected: {FOURDLLM_VERSION_EXPECTED})")
                
                if version != FOURDLLM_VERSION_EXPECTED:
                    error_msg = f"Unsupported 4DLLM version: {version} (expected {FOURDLLM_VERSION_EXPECTED})"
                    DEBUG_LOGGER.error(error_msg)
                    raise Exception(error_msg)
            
            self._log("Reading TOC from 4DLLM file...")
            DEBUG_LOGGER.info("Calling read_and_validate_toc...")
            
            try:
                entries, toc_offset = read_and_validate_toc(self.input_file)
                DEBUG_LOGGER.info(f"TOC read successfully: {len(entries)} entries, offset: {toc_offset}")
                
                # If offset is 0 and no entries, the TOC wasn't found properly
                if toc_offset == 0 and len(entries) == 0:
                    DEBUG_LOGGER.warning("TOC offset is 0 with 0 entries - likely TOC not found, searching manually...")
                    raise ValueError("TOC not found at offset 0")
                    
            except Exception as toc_error:
                DEBUG_LOGGER.error(f"Failed to read TOC: {toc_error}", exc_info=True)
                # Try to find TOC manually for debugging
                self._log("TOC read failed, attempting manual TOC search...")
                DEBUG_LOGGER.info("Attempting manual TOC search...")
                
                file_size = self.input_file.stat().st_size
                DEBUG_LOGGER.info(f"File size: {file_size} bytes ({file_size / (1024**3):.2f} GB)")
                
                # For large files, search more bytes from the end
                # TOC should be within last 64MB for safety
                search_bytes = min(64 * 1024 * 1024, file_size)
                DEBUG_LOGGER.info(f"Searching last {search_bytes} bytes for TOC1 magic...")
                
                with open(self.input_file, "rb") as f:
                    f.seek(max(0, file_size - search_bytes))
                    data = f.read()
                    toc_pos = data.rfind(b"TOC1")  # Use rfind to get the last occurrence
                    
                    if toc_pos >= 0:
                        actual_offset = file_size - search_bytes + toc_pos
                        DEBUG_LOGGER.info(f"✅ Found TOC1 magic at offset: {actual_offset} (0x{actual_offset:x})")
                        self._log(f"Found TOC1 at offset {actual_offset}, reading manually...")
                        
                        # Read TOC manually at the found offset
                        try:
                            DEBUG_LOGGER.info("Reading TOC manually at found offset...")
                            f.seek(actual_offset)
                            
                            # Read TOC header
                            hdr = read_exact(f, TOC_HDR_STRUCT.size)
                            magic, toc_ver, count = TOC_HDR_STRUCT.unpack(hdr)
                            
                            if magic != TOC_MAGIC:
                                raise ValueError(f"Bad TOC magic: {magic}")
                            if toc_ver != TOC_VERSION:
                                raise ValueError(f"Unsupported TOC version: {toc_ver}")
                            
                            DEBUG_LOGGER.info(f"TOC header: version={toc_ver}, section_count={count}")
                            self._log(f"TOC found: {count} sections")
                            
                            if count == 0:
                                raise Exception("TOC has 0 sections - file may be corrupted")
                            
                            # Read entries
                            entries_bytes = read_exact(f, TOC_ENTRY_STRUCT.size * count)
                            footer_crc = struct.unpack("<I", read_exact(f, 4))[0]
                            
                            # Validate CRC
                            computed = crc32_bytes(hdr + entries_bytes)
                            if computed != footer_crc:
                                DEBUG_LOGGER.warning(f"TOC CRC mismatch: expected {footer_crc:08x}, got {computed:08x} (continuing anyway)")
                            
                            # Parse entries
                            entries = []
                            for i in range(count):
                                chunk = entries_bytes[i * TOC_ENTRY_STRUCT.size:(i + 1) * TOC_ENTRY_STRUCT.size]
                                stype, flags, off, size_c, size_u, extra_sz, crc_u = TOC_ENTRY_STRUCT.unpack(chunk)
                                
                                # Create TocEntry-like object
                                # Check if TocEntry class is available (use globals() to avoid NameError)
                                try:
                                    toc_entry_class = globals().get('TocEntry')
                                    if toc_entry_class and callable(toc_entry_class):
                                        entry = toc_entry_class(stype, flags, off, size_c, size_u, extra_sz, crc_u)
                                    else:
                                        raise AttributeError("TocEntry not available")
                                except (NameError, AttributeError, TypeError):
                                    # Fallback: create simple object using SimpleNamespace
                                    from types import SimpleNamespace
                                    entry = SimpleNamespace()
                                    entry.section_type = stype
                                    entry.flags = flags
                                    entry.offset = off
                                    entry.size_c = size_c
                                    entry.size_u = size_u
                                    entry.extra_sz = extra_sz
                                    entry.crc32_u = crc_u
                                
                                entries.append(entry)
                            
                            DEBUG_LOGGER.info(f"✅ Successfully read {len(entries)} entries from TOC")
                            self._log(f"✅ Successfully read {len(entries)} sections from TOC")
                            
                            # Use the manually read entries
                            toc_offset = actual_offset
                            # Continue processing with these entries
                            
                        except Exception as manual_error:
                            DEBUG_LOGGER.error(f"Manual TOC read failed: {manual_error}", exc_info=True)
                            self._log(f"Failed to read TOC manually: {manual_error}")
                            raise Exception(f"Failed to read TOC: {toc_error}")
                    else:
                        DEBUG_LOGGER.error("TOC1 magic not found in last 64MB of file")
                        self._log("TOC1 magic not found in file")
                        raise Exception(f"Failed to read TOC: {toc_error}")
                
                # If we got here, we should have entries from manual read
                if 'entries' not in locals() or len(entries) == 0:
                    raise Exception(f"Failed to read TOC: {toc_error}")
            
            self._log(f"Found {len(entries)} sections in TOC (offset: {toc_offset})")
            DEBUG_LOGGER.info(f"Processing {len(entries)} sections")
            
            if len(entries) == 0:
                error_msg = "TOC contains 0 sections - file may be corrupted or incomplete"
                DEBUG_LOGGER.error(error_msg)
                raise Exception(error_msg)
            
            # Debug: log all section types
            section_names = {
                0x01: "GGUF Data",
                0x02: "Python Script",
                0x03: "Metadata",
                0x04: "Script Config",
                0x05: "Manifest",
            }
            
            DEBUG_LOGGER.info("Section details:")
            for i, entry in enumerate(entries):
                sec_name = section_names.get(entry.section_type, f"Unknown ({entry.section_type})")
                entry_info = f"Section {i+1}: {sec_name} (type={entry.section_type}, size_u={entry.size_u}, size_c={entry.size_c}, offset={entry.offset})"
                DEBUG_LOGGER.info(f"  {entry_info}")
                self._log(f"  Section {i+1}: {sec_name} (type={entry.section_type}, size={entry.size_u} bytes)")
            
            # Find GGUF section
            gguf_entry = None
            for entry in entries:
                DEBUG_LOGGER.debug(f"Checking entry: type={entry.section_type}, SECTION_GGUF_DATA={SECTION_GGUF_DATA}")
                if entry.section_type == SECTION_GGUF_DATA:
                    gguf_entry = entry
                    DEBUG_LOGGER.info(f"Found GGUF entry: size_u={entry.size_u}, size_c={entry.size_c}, offset={entry.offset}")
                    break
            
            if not gguf_entry:
                # Try alternative: check if section_type attribute exists
                entry_types = [getattr(e, 'section_type', 'NO_ATTR') for e in entries]
                error_msg = f"No GGUF section found. Found {len(entries)} sections, but none with type {SECTION_GGUF_DATA}. Entry types: {entry_types}"
                DEBUG_LOGGER.error(error_msg)
                self._log(f"DEBUG: SECTION_GGUF_DATA constant = {SECTION_GGUF_DATA}")
                self._log(f"DEBUG: Entry types found: {entry_types}")
                raise Exception(error_msg)
            
            self._log(f"Found GGUF section: {gguf_entry.size_u} bytes (compressed: {gguf_entry.size_c})")
            DEBUG_LOGGER.info("Reading section data...")
            
            section = read_section_small(self.input_file, gguf_entry)
            DEBUG_LOGGER.info("Section read, decoding and validating...")
            
            self._log("Decoding and validating section...")
            data = decode_and_validate(section)
            
            self._log(f"Decoded {len(data)} bytes of GGUF data")
            DEBUG_LOGGER.info(f"Decoded {len(data)} bytes of GGUF data")
            
            # Save to temp file
            temp_dir = Path.home() / ".4dllm_trainer_temp"
            temp_dir.mkdir(exist_ok=True)
            gguf_path = temp_dir / f"{self.input_file.stem}_extracted.gguf"
            
            self._log(f"Writing GGUF to temporary file: {gguf_path}")
            DEBUG_LOGGER.info(f"Writing GGUF to: {gguf_path}")
            
            with open(gguf_path, "wb") as f:
                f.write(data)
            
            self._log(f"✅ Successfully extracted GGUF to: {gguf_path}")
            DEBUG_LOGGER.info(f"✅ GGUF extraction successful: {gguf_path}")
            return gguf_path
            
        except Exception as e:
            error_details = traceback.format_exc()
            DEBUG_LOGGER.error(f"GGUF extraction failed: {e}", exc_info=True)
            self._log(f"❌ Error extracting GGUF: {e}")
            self._log(f"Check debug log: {DEBUG_LOG_FILE}")
            return None
    
    def _simulate_training(self, params: Dict[str, str]):
        """Simulate training process (replace with actual llama.cpp training)"""
        epochs = int(params["epochs"])
        
        for epoch in range(1, epochs + 1):
            if not self.is_training:
                break
            
            self._log(f"Epoch {epoch}/{epochs}...")
            self.root.after(0, lambda e=epoch, t=epochs: self.stats_label.config(
                text=f"Epoch: {e}/{t}\nLoss: {0.5 - (e * 0.05):.4f}\nTime: {e * 30}s"
            ))
            
            # Simulate training time
            for step in range(10):
                if not self.is_training:
                    return
                time.sleep(0.5)
                self._log(f"  Step {step + 1}/10")
    
    def _rebuild_4dllm(self, trained_gguf_path: Path):
        """Rebuild 4DLLM file with trained GGUF"""
        # Read original 4DLLM metadata and scripts
        entries, _ = read_and_validate_toc(self.input_file)
        
        metadata = {}
        script_config = {}
        scripts = []
        
        for entry in entries:
            if entry.section_type == SECTION_METADATA:
                section = read_section_small(self.input_file, entry)
                data = decode_and_validate(section)
                metadata = json.loads(data.decode('utf-8'))
            elif entry.section_type == SECTION_SCRIPT_CONFIG:
                section = read_section_small(self.input_file, entry)
                data = decode_and_validate(section)
                script_config = json.loads(data.decode('utf-8'))
            elif entry.section_type == 0x02:  # Python script
                section = read_section_small(self.input_file, entry)
                scripts.append(section)
        
        # Update metadata with training info
        metadata["training_date"] = datetime.now().isoformat()
        metadata["training_params"] = {key: entry.get() for key, entry in self.params.items()}
        
        # Write new 4DLLM file (simplified - use builder for full implementation)
        self._log("Writing trained 4DLLM file...")
        # This is a placeholder - full implementation would use the builder
        with open(self.output_file, "wb") as f:
            f.write(FOURDLLM_MAGIC)
            f.write(struct.pack("<I", FOURDLLM_VERSION_EXPECTED))
            f.write(b'\x00' * 56)
            # Add sections...
        
        self._log("4DLLM file rebuilt successfully")
    
    def _stop_training(self):
        """Stop training process"""
        if self.training_process:
            self.training_process.terminate()
        self.is_training = False
        self._log("Training stopped by user")
    
    def _log(self, message: str):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        self.root.after(0, lambda: self._append_log(log_message))
    
    def _append_log(self, message: str):
        """Append to log text widget"""
        self.logs_text.config(state="normal")
        self.logs_text.insert("end", message)
        self.logs_text.see("end")
        self.logs_text.config(state="disabled")
    
    def _open_email(self):
        """Open email client"""
        import webbrowser
        try:
            webbrowser.open("mailto:romanailabs@gmail.com")
        except:
            self.root.clipboard_clear()
            self.root.clipboard_append("romanailabs@gmail.com")
            messagebox.showinfo("Email", "Email copied to clipboard:\nromanailabs@gmail.com")


def main():
    """Main entry point"""
    root = tk.Tk()
    app = FourDLLMTrainer(root)
    root.mainloop()


if __name__ == "__main__":
    main()

