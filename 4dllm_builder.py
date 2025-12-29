#!/usr/bin/env python3
"""
4DLLM Builder - GUI Application
A world-class, user-friendly interface for converting GGUF to 4DLLM with Python script injection.
Uses tkinter for maximum compatibility (no external GUI dependencies).
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import struct
import json
import zlib
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 4DLLM Format Constants
FOURDLLM_MAGIC = b'4DLL'
FOURDLLM_VERSION = 1
FOURDLLM_HEADER_SIZE = 64

# Section Types
SECTION_GGUF_DATA = 0x01
SECTION_PYTHON_SCRIPT = 0x02
SECTION_METADATA = 0x03
SECTION_SCRIPT_CONFIG = 0x04

# Modern color scheme
COLORS = {
    'bg_primary': '#1e1e1e',
    'bg_secondary': '#2d2d2d',
    'bg_tertiary': '#3a3a3a',
    'fg_primary': '#ffffff',
    'fg_secondary': '#cccccc',
    'accent': '#0078d4',
    'accent_hover': '#106ebe',
    'success': '#00ff00',
    'warning': '#ffaa00',
    'error': '#ff4444',
    'border': '#3a3a3a'
}

# Built-in script templates
SCRIPT_TEMPLATES = {
    'Math Enhancer': '''# Math Enhancement Script
import math
import re

def evaluate_math(expr: str):
    """Safely evaluate mathematical expression."""
    expr = expr.replace(' ', '')
    if not re.match(r'^[0-9+\\-*/().\\s]+$', expr):
        return None
    try:
        return eval(expr, {"__builtins__": {}, "math": math})
    except:
        return None

if 'input' in context:
    text = context.get('input', '')
    patterns = [
        r'what is\\s+([0-9+\\-*/().\\s]+)\\?',
        r'calculate\\s+([0-9+\\-*/().\\s]+)',
        r'([0-9+\\-*/().\\s]+)\\s*=\\s*\\?',
    ]
    for pattern in patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            expr = match.group(1).strip()
            result = evaluate_math(expr)
            if result is not None:
                text = text.replace(match.group(0), f"{match.group(0)} → {result}")
    context['input'] = text
    result = {'enhanced': True, 'type': 'math'}
''',

    'Code Analyzer': '''# Code Analysis Script
import ast
import re

def analyze_code(text: str):
    """Analyze code in text."""
    code_blocks = re.findall(r'```(?:python|py)?\\n(.*?)```', text, re.DOTALL)
    analysis = {'code_blocks': len(code_blocks), 'functions': [], 'classes': []}
    for code in code_blocks:
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    analysis['functions'].append(node.name)
                if isinstance(node, ast.ClassDef):
                    analysis['classes'].append(node.name)
        except:
            pass
    return analysis

if 'input' in context:
    analysis = analyze_code(context.get('input', ''))
    context['code_analysis'] = analysis
    result = {'enhanced': True, 'type': 'code', 'analysis': analysis}
''',

    'Reasoning Chain': '''# Reasoning Enhancement Script
def add_reasoning(text: str):
    """Add reasoning structure."""
    return f"""Let's think step by step:
1. Understand the problem
2. Break it down into components
3. Analyze each component
4. Synthesize the solution
5. Verify the answer

Problem: {text}
"""
if 'input' in context:
    context['input'] = add_reasoning(context.get('input', ''))
    result = {'enhanced': True, 'type': 'reasoning'}
'''
}


class FourDLLMBuilder:
    """Builder for 4DLLM format files."""
    
    def __init__(self, gguf_file: str):
        self.gguf_file = Path(gguf_file)
        if not self.gguf_file.exists():
            raise FileNotFoundError(f"GGUF file not found: {gguf_file}")
        self.scripts: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {}
        self.gguf_data: Optional[bytes] = None
        
    def add_script(self, content: str, name: str, description: str = "", 
                   priority: int = 0, enabled: bool = True):
        """Add a Python script."""
        self.scripts.append({
            'name': name,
            'description': description,
            'content': content,
            'priority': priority,
            'enabled': enabled,
            'size': len(content.encode('utf-8'))
        })
    
    def build(self, output_path: str, compress: bool = True) -> str:
        """Build the 4DLLM file."""
        output_path = Path(output_path)
        
        with open(self.gguf_file, 'rb') as f:
            self.gguf_data = f.read()
        
        self.scripts.sort(key=lambda x: x['priority'], reverse=True)
        
        with open(output_path, 'wb') as f:
            # Header
            f.write(FOURDLLM_MAGIC)
            f.write(struct.pack('<I', FOURDLLM_VERSION))
            f.write(b'\x00' * 56)
            
            # GGUF data
            self._write_section(f, SECTION_GGUF_DATA, self.gguf_data, compress=False)
            
            # Metadata
            if self.metadata:
                metadata_json = json.dumps(self.metadata).encode('utf-8')
                self._write_section(f, SECTION_METADATA, metadata_json, compress=compress)
            
            # Script config
            script_config = {
                'script_count': len(self.scripts),
                'scripts': [{'name': s['name'], 'priority': s['priority'], 
                           'enabled': s['enabled']} for s in self.scripts]
            }
            config_json = json.dumps(script_config).encode('utf-8')
            self._write_section(f, SECTION_SCRIPT_CONFIG, config_json, compress=compress)
            
            # Scripts
            for script in self.scripts:
                script_bytes = script['content'].encode('utf-8')
                self._write_section(f, SECTION_PYTHON_SCRIPT, script_bytes, 
                                  compress=compress, extra_data={'name': script['name']})
        
        return str(output_path)
    
    def _write_section(self, f, section_type: int, data: bytes, 
                      compress: bool = True, extra_data: Optional[Dict] = None):
        """Write a section."""
        if compress:
            data = zlib.compress(data, level=9)
            compressed = True
        else:
            compressed = False
        
        extra_data_bytes = b''
        if extra_data:
            extra_data_bytes = json.dumps(extra_data).encode('utf-8')
        
        # Section header: type (1B), compressed (1B), padding (2B), data_size (8B), extra_size (4B)
        f.write(struct.pack('<BB2xQI',
            section_type, 1 if compressed else 0, len(data), len(extra_data_bytes)))
        
        if extra_data_bytes:
            f.write(extra_data_bytes)
        f.write(data)


class FourDLLMBuilderGUI:
    """Modern GUI for 4DLLM Builder."""
    
    def __init__(self, root):
        self.root = root
        self.gguf_file = None
        self.scripts = []
        self.setup_window()
        self.setup_ui()
        
    def setup_window(self):
        """Configure window."""
        self.root.title("✨ 4DLLM Builder - Python Script Injector")
        self.root.geometry("900x700")
        self.root.configure(bg=COLORS['bg_primary'])
        
        # Center window
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def setup_ui(self):
        """Create UI."""
        # Header
        header = tk.Frame(self.root, bg=COLORS['bg_secondary'], height=80)
        header.pack(fill='x')
        header.pack_propagate(False)
        
        title = tk.Label(header, text="✨ 4DLLM Builder", 
                        font=("Segoe UI", 24, "bold"),
                        bg=COLORS['bg_secondary'], fg=COLORS['accent'])
        title.pack(pady=20)
        
        # Main container
        main = tk.Frame(self.root, bg=COLORS['bg_primary'])
        main.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Step 1: Select GGUF File
        step1_frame = ttk.LabelFrame(main, text="📁 Step 1: Select GGUF File", padding=15)
        step1_frame.pack(fill='x', pady=10)
        
        self.file_label = tk.Label(step1_frame, text="No file selected", 
                                   font=("Segoe UI", 10),
                                   bg=COLORS['bg_primary'], fg=COLORS['fg_secondary'],
                                   anchor='w')
        self.file_label.pack(fill='x', pady=5)
        
        select_btn = tk.Button(step1_frame, text="📂 Select GGUF File",
                              command=self.select_gguf_file,
                              bg=COLORS['accent'], fg=COLORS['fg_primary'],
                              font=("Segoe UI", 10, "bold"),
                              relief='flat', padx=20, pady=10,
                              cursor='hand2')
        select_btn.pack(pady=5)
        
        # Step 2: Add Python Scripts
        step2_frame = ttk.LabelFrame(main, text="🐍 Step 2: Add Python Scripts", padding=15)
        step2_frame.pack(fill='both', expand=True, pady=10)
        
        # Script buttons frame
        buttons_frame = tk.Frame(step2_frame, bg=COLORS['bg_primary'])
        buttons_frame.pack(fill='x', pady=5)
        
        tk.Label(buttons_frame, text="Built-in Scripts:", 
                font=("Segoe UI", 10, "bold"),
                bg=COLORS['bg_primary'], fg=COLORS['fg_primary']).pack(side='left', padx=5)
        
        for script_name in SCRIPT_TEMPLATES.keys():
            btn = tk.Button(buttons_frame, text=f"+ {script_name}",
                           command=lambda n=script_name: self.add_builtin_script(n),
                           bg=COLORS['bg_tertiary'], fg=COLORS['fg_primary'],
                           font=("Segoe UI", 9),
                           relief='flat', padx=10, pady=5,
                           cursor='hand2')
            btn.pack(side='left', padx=5)
        
        custom_btn = tk.Button(buttons_frame, text="+ Custom Script File",
                              command=self.add_custom_script,
                              bg=COLORS['accent'], fg=COLORS['fg_primary'],
                              font=("Segoe UI", 9, "bold"),
                              relief='flat', padx=10, pady=5,
                              cursor='hand2')
        custom_btn.pack(side='left', padx=5)
        
        # Scripts list
        list_frame = tk.Frame(step2_frame, bg=COLORS['bg_primary'])
        list_frame.pack(fill='both', expand=True, pady=10)
        
        # Scrollable list
        canvas = tk.Canvas(list_frame, bg=COLORS['bg_secondary'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        self.scripts_container = tk.Frame(canvas, bg=COLORS['bg_secondary'])
        
        self.scripts_container.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.scripts_container, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.scripts_canvas = canvas
        
        # Step 3: Build
        step3_frame = tk.Frame(main, bg=COLORS['bg_primary'])
        step3_frame.pack(fill='x', pady=10)
        
        build_btn = tk.Button(step3_frame, text="🚀 Build 4DLLM File",
                             command=self.build_file,
                             bg=COLORS['success'], fg=COLORS['bg_primary'],
                             font=("Segoe UI", 12, "bold"),
                             relief='flat', padx=30, pady=15,
                             cursor='hand2')
        build_btn.pack()
        
        # Status bar
        self.status_label = tk.Label(self.root, text="Ready", 
                                    font=("Segoe UI", 9),
                                    bg=COLORS['bg_secondary'], fg=COLORS['fg_secondary'],
                                    anchor='w', padx=10, pady=5)
        self.status_label.pack(fill='x', side='bottom')
    
    def select_gguf_file(self):
        """Select GGUF file."""
        file_path = filedialog.askopenfilename(
            title="Select GGUF File",
            filetypes=[("GGUF files", "*.gguf"), ("All files", "*.*")]
        )
        if file_path:
            self.gguf_file = file_path
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path) / (1024 * 1024)
            self.file_label.config(
                text=f"✓ {file_name} ({file_size:.2f} MB)",
                fg=COLORS['success']
            )
            self.update_status(f"Selected: {file_name}")
    
    def add_builtin_script(self, script_name: str):
        """Add built-in script."""
        if script_name not in SCRIPT_TEMPLATES:
            return
        
        script_content = SCRIPT_TEMPLATES[script_name]
        self.add_script_to_list(script_name, script_content, is_builtin=True)
        self.update_status(f"Added built-in script: {script_name}")
    
    def add_custom_script(self):
        """Add custom script from file."""
        file_path = filedialog.askopenfilename(
            title="Select Python Script",
            filetypes=[("Python files", "*.py"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    script_content = f.read()
                
                script_name = os.path.basename(file_path).replace('.py', '')
                self.add_script_to_list(script_name, script_content, is_builtin=False)
                self.update_status(f"Added custom script: {script_name}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load script:\n{e}")
    
    def add_script_to_list(self, name: str, content: str, is_builtin: bool = False):
        """Add script to the list UI."""
        script_frame = tk.Frame(self.scripts_container, bg=COLORS['bg_tertiary'], 
                               relief='flat', bd=1)
        script_frame.pack(fill='x', padx=5, pady=5)
        
        # Script info
        info_frame = tk.Frame(script_frame, bg=COLORS['bg_tertiary'])
        info_frame.pack(fill='x', padx=10, pady=5)
        
        name_label = tk.Label(info_frame, text=f"🐍 {name}",
                             font=("Segoe UI", 10, "bold"),
                             bg=COLORS['bg_tertiary'], fg=COLORS['fg_primary'],
                             anchor='w')
        name_label.pack(side='left')
        
        if is_builtin:
            badge = tk.Label(info_frame, text="Built-in",
                           font=("Segoe UI", 8),
                           bg=COLORS['accent'], fg=COLORS['fg_primary'],
                           padx=5, pady=2)
            badge.pack(side='left', padx=5)
        
        size_label = tk.Label(info_frame, 
                            text=f"({len(content.encode('utf-8'))} bytes)",
                            font=("Segoe UI", 8),
                            bg=COLORS['bg_tertiary'], fg=COLORS['fg_secondary'])
        size_label.pack(side='left', padx=5)
        
        # Remove button
        remove_btn = tk.Button(info_frame, text="✕ Remove",
                              command=lambda: self.remove_script(script_frame, name),
                              bg=COLORS['error'], fg=COLORS['fg_primary'],
                              font=("Segoe UI", 8),
                              relief='flat', padx=10, pady=2,
                              cursor='hand2')
        remove_btn.pack(side='right')
        
        # Store script data
        script_data = {
            'frame': script_frame,
            'name': name,
            'content': content,
            'is_builtin': is_builtin
        }
        self.scripts.append(script_data)
        
        # Update canvas scroll
        self.scripts_container.update_idletasks()
        self.scripts_canvas.configure(scrollregion=self.scripts_canvas.bbox("all"))
    
    def remove_script(self, frame, name: str):
        """Remove script from list."""
        frame.destroy()
        self.scripts = [s for s in self.scripts if s['name'] != name]
        self.update_status(f"Removed script: {name}")
    
    def build_file(self):
        """Build 4DLLM file."""
        if not self.gguf_file:
            messagebox.showwarning("Warning", "Please select a GGUF file first!")
            return
        
        if not self.scripts:
            messagebox.showwarning("Warning", "Please add at least one Python script!")
            return
        
        # Ask for output file
        output_path = filedialog.asksaveasfilename(
            title="Save 4DLLM File",
            defaultextension=".4dllm",
            filetypes=[("4DLLM files", "*.4dllm"), ("All files", "*.*")]
        )
        
        if not output_path:
            return
        
        try:
            self.update_status("Building 4DLLM file...")
            self.root.update()
            
            # Create builder
            builder = FourDLLMBuilder(self.gguf_file)
            
            # Add scripts
            for script in self.scripts:
                builder.add_script(
                    content=script['content'],
                    name=script['name'],
                    description=f"{'Built-in' if script['is_builtin'] else 'Custom'} script",
                    priority=10 if script['is_builtin'] else 5
                )
            
            # Build
            result_path = builder.build(output_path, compress=True)
            
            file_size = os.path.getsize(result_path) / (1024 * 1024)
            
            messagebox.showinfo("Success", 
                f"4DLLM file created successfully!\n\n"
                f"File: {os.path.basename(result_path)}\n"
                f"Size: {file_size:.2f} MB\n"
                f"Scripts embedded: {len(self.scripts)}")
            
            self.update_status(f"✓ Built: {os.path.basename(result_path)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to build 4DLLM file:\n{e}")
            self.update_status(f"✗ Error: {str(e)}")
            logger.error(f"Build error: {e}", exc_info=True)
    
    def update_status(self, message: str):
        """Update status bar."""
        self.status_label.config(text=message)
        self.root.update_idletasks()


def main():
    """Main entry point."""
    root = tk.Tk()
    app = FourDLLMBuilderGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
