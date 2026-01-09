#!/usr/bin/env python3
"""
VulnScope - Blue Team Vulnerability Scanner
============================================
A modern GUI-based vulnerability scanning tool for security professionals.
Integrates Nmap, Nuclei, Nikto, Gobuster, and Masscan.

Requirements:
    - Python 3.8+
    - tkinter (usually comes with Python)
    - Security tools installed and in PATH (nmap, nuclei, nikto, gobuster, masscan)

Usage:
    python vulnscope.py

    use this on permitted/owned systems only.

Author: https://github.com/whatiscybersecurity
License: MIT
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import threading
import queue
import os
import sys
import json
import shutil
import re
import urllib.request
import zipfile
import tempfile
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable
import webbrowser

# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class ScanProfile:
    """Scan profile configuration"""
    name: str
    description: str
    color: str
    nmap: List[str]
    nuclei: List[str]
    nikto: List[str]
    gobuster: List[str]
    masscan: List[str]

PROFILES: Dict[str, ScanProfile] = {
    'stealth': ScanProfile(
        name='Stealth',
        description='Low and slow to avoid detection',
        color='#6366f1',
        nmap=['-sS', '-T2', '-f', '--data-length', '24', '--randomize-hosts'],
        nuclei=['-rl', '10', '-c', '5', '-timeout', '15'],
        nikto=['-Tuning', '1', '-timeout', '30'],
        gobuster=['-t', '5', '--delay', '500ms'],
        masscan=['--rate', '100'],
    ),
    'speed': ScanProfile(
        name='Speed',
        description='Fast scanning for quick assessments',
        color='#f59e0b',
        nmap=['-sS', '-T4', '--min-rate', '1000', '-n', '--open'],
        nuclei=['-rl', '150', '-c', '50', '-timeout', '5'],
        nikto=['-Tuning', '9', '-timeout', '5'],
        gobuster=['-t', '50', '--no-error'],
        masscan=['--rate', '10000'],
    ),
    'accuracy': ScanProfile(
        name='Accuracy',
        description='Thorough and comprehensive results',
        color='#10b981',
        nmap=['-sS', '-sV', '-sC', '-A', '--version-all', '-T3'],
        nuclei=['-rl', '50', '-c', '25', '-timeout', '10', '-retries', '3'],
        nikto=['-Tuning', '123bde', '-timeout', '15'],
        gobuster=['-t', '20'],
        masscan=['--rate', '1000'],
    ),
    'discovery': ScanProfile(
        name='Discovery',
        description='Network topology mapping',
        color='#8b5cf6',
        nmap=['-sn', '-PE', '-PP', '-PM', '--traceroute'],
        nuclei=['-tags', 'network,dns', '-rl', '100'],
        nikto=['-Tuning', '0'],
        gobuster=['-t', '30'],
        masscan=['--rate', '5000'],
    ),
    'vuln': ScanProfile(
        name='Vulnerability',
        description='Deep vulnerability assessment',
        color='#ef4444',
        nmap=['-sV', '--script', 'vuln,exploit,auth', '-T3'],
        nuclei=['-severity', 'critical,high,medium', '-rl', '75'],
        nikto=['-Tuning', '4567890abc'],
        gobuster=['-t', '25'],
        masscan=['--rate', '2000'],
    ),
    'web': ScanProfile(
        name='Web App',
        description='Web application focused testing',
        color='#06b6d4',
        nmap=['-sV', '-p', '80,443,8080,8443', '--script', 'http-*'],
        nuclei=['-tags', 'cve,oast,sqli,xss,rce,lfi', '-rl', '100'],
        nikto=['-Tuning', '123456789abc', '-ssl'],
        gobuster=['-t', '30', '-x', 'php,asp,aspx,jsp,html,js'],
        masscan=['-p', '80,443,8080,8443', '--rate', '5000'],
    ),
}

TOOLS = {
    'nmap': {'name': 'Nmap', 'desc': 'Network mapper & port scanner'},
    'nuclei': {'name': 'Nuclei', 'desc': 'Template-based vulnerability scanner'},
    'nikto': {'name': 'Nikto', 'desc': 'Web server scanner'},
    'gobuster': {'name': 'Gobuster', 'desc': 'Directory brute-forcer'},
    'masscan': {'name': 'Masscan', 'desc': 'High-speed port scanner'},
}

# Tool installation info - Windows compatible with auto-detection support
TOOL_INSTALL_INFO = {
    'nmap': {
        'windows': {
            'url': 'https://nmap.org/download.html',
            'instructions': 'Download the Windows installer from nmap.org and run it.',
            'winget': 'winget install Insecure.Nmap',
            'choco': 'choco install nmap',
        },
        'linux': {
            'apt': 'sudo apt install -y nmap',
            'yum': 'sudo yum install -y nmap',
            'dnf': 'sudo dnf install -y nmap',
            'pacman': 'sudo pacman -S --noconfirm nmap',
        },
        'darwin': {
            'brew': 'brew install nmap',
        },
    },
    'nuclei': {
        'windows': {
            'url': 'https://github.com/projectdiscovery/nuclei/releases',
            'instructions': 'Download the Windows binary from GitHub releases and add to PATH.',
            'go': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'choco': 'choco install nuclei',
        },
        'linux': {
            'go': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'apt': 'sudo apt install -y nuclei',
            'snap': 'sudo snap install nuclei',
        },
        'darwin': {
            'brew': 'brew install nuclei',
            'go': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
        },
    },
    'nikto': {
        'windows': {
            'url': 'https://github.com/sullo/nikto',
            'instructions': 'Clone the repo and run with Perl. Requires Perl installation (e.g., Strawberry Perl).',
            'git': 'git clone https://github.com/sullo/nikto.git "%USERPROFILE%\\nikto"',
        },
        'linux': {
            'apt': 'sudo apt install -y nikto',
            'yum': 'sudo yum install -y nikto',
            'dnf': 'sudo dnf install -y nikto',
        },
        'darwin': {
            'brew': 'brew install nikto',
        },
    },
    'gobuster': {
        'windows': {
            'url': 'https://github.com/OJ/gobuster/releases',
            'instructions': 'Download the Windows binary from GitHub releases and add to PATH.',
            'go': 'go install github.com/OJ/gobuster/v3@latest',
            'choco': 'choco install gobuster',
        },
        'linux': {
            'apt': 'sudo apt install -y gobuster',
            'go': 'go install github.com/OJ/gobuster/v3@latest',
            'snap': 'sudo snap install gobuster',
        },
        'darwin': {
            'brew': 'brew install gobuster',
            'go': 'go install github.com/OJ/gobuster/v3@latest',
        },
    },
    'masscan': {
        'windows': {
            'url': 'https://github.com/robertdavidgraham/masscan/releases',
            'instructions': 'Download pre-built Windows binary from releases or compile with Visual Studio.',
            'choco': 'choco install masscan',
        },
        'linux': {
            'apt': 'sudo apt install -y masscan',
            'yum': 'sudo yum install -y masscan',
            'dnf': 'sudo dnf install -y masscan',
            'source': 'git clone https://github.com/robertdavidgraham/masscan && cd masscan && make && sudo make install',
        },
        'darwin': {
            'brew': 'brew install masscan',
        },
    },
}

# ============================================================================
# THEME / COLORS
# ============================================================================

THEME = {
    'bg_primary': '#0a0a0f',
    'bg_secondary': '#12121a',
    'bg_tertiary': '#1a1a24',
    'bg_input': '#0d0d12',
    'text_primary': '#e4e4e7',
    'text_secondary': '#a1a1aa',
    'text_muted': '#71717a',
    'text_dark': '#52525b',
    'border': '#2a2a35',
    'accent': '#6366f1',
    'accent_hover': '#818cf8',
    'success': '#10b981',
    'warning': '#f59e0b',
    'danger': '#ef4444',
    'info': '#06b6d4',
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def check_tool_installed(tool: str) -> bool:
    """Check if a tool is installed and available in PATH"""
    return shutil.which(tool) is not None

def get_available_tools() -> Dict[str, bool]:
    """Get dictionary of tools and their availability"""
    return {tool: check_tool_installed(tool) for tool in TOOLS.keys()}

def sanitize_filename(name: str) -> str:
    """Sanitize string for use in filenames"""
    return re.sub(r'[^a-zA-Z0-9.-]', '_', name)[:50]

def validate_target(target: str) -> tuple[bool, str]:
    """Validate target input (supports multiple comma-separated targets)"""
    if not target.strip():
        return False, "Target cannot be empty"
    
    # Check for dangerous characters (allow comma for multiple targets)
    dangerous = [';', '&&', '||', '|', '`', '$', '\n', '\r']
    for char in dangerous:
        if char in target:
            return False, f"Invalid character in target: {char}"
    
    return True, ""

def parse_targets(target_input: str) -> List[str]:
    """Parse comma-separated targets into a list"""
    targets = []
    
    # Split by comma and clean up
    for t in target_input.split(','):
        t = t.strip()
        if t:
            targets.append(t)
    
    return targets

def validate_single_target(target: str) -> tuple[bool, str]:
    """Validate a single target"""
    if not target.strip():
        return False, "Target cannot be empty"
    
    # Check for dangerous characters
    dangerous = [';', '&&', '||', '|', '`', '$', '\n', '\r', ',']
    for char in dangerous:
        if char in target:
            return False, f"Invalid character in target: {char}"
    
    return True, ""

def format_file_size(size: int) -> str:
    """Format file size in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

def get_platform() -> str:
    """Get current platform identifier"""
    if sys.platform == 'win32':
        return 'windows'
    elif sys.platform == 'darwin':
        return 'darwin'
    else:
        return 'linux'

# ============================================================================
# TOOL INSTALLER & PATH MANAGEMENT
# ============================================================================

# Common installation paths for tools on different platforms
TOOL_INSTALL_PATHS = {
    'windows': [
        os.path.expandvars(r'%USERPROFILE%\go\bin'),
        os.path.expandvars(r'%USERPROFILE%\scoop\shims'),
        os.path.expandvars(r'%USERPROFILE%\AppData\Local\Microsoft\WinGet\Packages'),
        os.path.expandvars(r'%ProgramFiles%\Nmap'),
        os.path.expandvars(r'%ProgramFiles(x86)%\Nmap'),
        r'C:\Program Files\Nmap',
        r'C:\Program Files (x86)\Nmap',
        r'C:\tools',
        r'C:\ProgramData\chocolatey\bin',
        os.path.expandvars(r'%USERPROFILE%\nuclei'),
        os.path.expandvars(r'%USERPROFILE%\gobuster'),
        os.path.expandvars(r'%LOCALAPPDATA%\Programs'),
    ],
    'darwin': [
        '/usr/local/bin',
        '/opt/homebrew/bin',
        os.path.expanduser('~/go/bin'),
        '/usr/local/go/bin',
    ],
    'linux': [
        '/usr/bin',
        '/usr/local/bin',
        '/snap/bin',
        os.path.expanduser('~/go/bin'),
        '/usr/local/go/bin',
        os.path.expanduser('~/.local/bin'),
    ],
}

# Tool-specific executable names (some differ on Windows)
TOOL_EXECUTABLES = {
    'nmap': {'windows': 'nmap.exe', 'default': 'nmap'},
    'nuclei': {'windows': 'nuclei.exe', 'default': 'nuclei'},
    'nikto': {'windows': 'nikto.pl', 'default': 'nikto'},
    'gobuster': {'windows': 'gobuster.exe', 'default': 'gobuster'},
    'masscan': {'windows': 'masscan.exe', 'default': 'masscan'},
}


class PathManager:
    """Manages PATH environment variable across platforms"""
    
    @staticmethod
    def get_tool_executable(tool: str) -> str:
        """Get the executable name for a tool on current platform"""
        platform = get_platform()
        tool_info = TOOL_EXECUTABLES.get(tool, {})
        return tool_info.get(platform, tool_info.get('default', tool))
    
    @staticmethod
    def find_tool_in_common_paths(tool: str) -> Optional[str]:
        """Search for a tool in common installation paths"""
        platform = get_platform()
        paths = TOOL_INSTALL_PATHS.get(platform, [])
        executable = PathManager.get_tool_executable(tool)
        
        for path in paths:
            if not os.path.exists(path):
                continue
            
            # Check directly in the path
            full_path = os.path.join(path, executable)
            if os.path.isfile(full_path):
                return path
            
            # Search subdirectories (one level deep)
            try:
                for item in os.listdir(path):
                    subdir = os.path.join(path, item)
                    if os.path.isdir(subdir):
                        full_path = os.path.join(subdir, executable)
                        if os.path.isfile(full_path):
                            return subdir
            except PermissionError:
                continue
        
        return None
    
    @staticmethod
    def is_path_in_env(path: str) -> bool:
        """Check if a path is already in the PATH environment variable"""
        current_path = os.environ.get('PATH', '')
        path_sep = ';' if sys.platform == 'win32' else ':'
        paths = current_path.split(path_sep)
        
        # Normalize paths for comparison
        normalized_path = os.path.normpath(path).lower() if sys.platform == 'win32' else os.path.normpath(path)
        normalized_paths = [os.path.normpath(p).lower() if sys.platform == 'win32' else os.path.normpath(p) for p in paths]
        
        return normalized_path in normalized_paths
    
    @staticmethod
    def add_to_session_path(path: str) -> bool:
        """Add a path to the current session's PATH"""
        if PathManager.is_path_in_env(path):
            return True
        
        path_sep = ';' if sys.platform == 'win32' else ':'
        os.environ['PATH'] = path + path_sep + os.environ.get('PATH', '')
        return True
    
    @staticmethod
    def add_to_permanent_path_windows(path: str, callback: Callable[[str, str], None]) -> bool:
        """Add a path to Windows permanent user PATH"""
        try:
            import winreg
            
            # Open the user environment key
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r'Environment',
                0,
                winreg.KEY_ALL_ACCESS
            )
            
            try:
                current_path, _ = winreg.QueryValueEx(key, 'Path')
            except WindowsError:
                current_path = ''
            
            # Check if already in PATH
            if path.lower() in current_path.lower():
                callback(f"Path already in user PATH: {path}", 'info')
                winreg.CloseKey(key)
                return True
            
            # Add to PATH
            new_path = current_path + ';' + path if current_path else path
            winreg.SetValueEx(key, 'Path', 0, winreg.REG_EXPAND_SZ, new_path)
            winreg.CloseKey(key)
            
            # Broadcast environment change
            try:
                import ctypes
                HWND_BROADCAST = 0xFFFF
                WM_SETTINGCHANGE = 0x1A
                ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, 'Environment')
            except:
                pass
            
            callback(f"Added to user PATH: {path}", 'success')
            callback("Note: You may need to restart applications to see the change.", 'info')
            return True
            
        except Exception as e:
            callback(f"Failed to modify PATH: {str(e)}", 'error')
            return False
    
    @staticmethod
    def add_to_permanent_path_unix(path: str, callback: Callable[[str, str], None]) -> bool:
        """Add a path to Unix shell profile"""
        shell = os.environ.get('SHELL', '/bin/bash')
        
        # Determine profile file
        if 'zsh' in shell:
            profile_files = [os.path.expanduser('~/.zshrc')]
        elif 'fish' in shell:
            profile_files = [os.path.expanduser('~/.config/fish/config.fish')]
        else:
            profile_files = [
                os.path.expanduser('~/.bashrc'),
                os.path.expanduser('~/.bash_profile'),
                os.path.expanduser('~/.profile'),
            ]
        
        export_line = f'export PATH="{path}:$PATH"'
        
        for profile_file in profile_files:
            if os.path.exists(profile_file):
                try:
                    # Check if already present
                    with open(profile_file, 'r') as f:
                        content = f.read()
                    
                    if path in content:
                        callback(f"Path already in {profile_file}", 'info')
                        return True
                    
                    # Append to file
                    with open(profile_file, 'a') as f:
                        f.write(f'\n# Added by VulnScope\n{export_line}\n')
                    
                    callback(f"Added to {profile_file}", 'success')
                    callback("Run 'source " + profile_file + "' or restart terminal to apply.", 'info')
                    return True
                    
                except Exception as e:
                    callback(f"Failed to modify {profile_file}: {str(e)}", 'error')
        
        callback("Could not find shell profile to modify.", 'warning')
        return False
    
    @staticmethod
    def add_to_permanent_path(path: str, callback: Callable[[str, str], None]) -> bool:
        """Add a path to permanent PATH (platform-specific)"""
        if sys.platform == 'win32':
            return PathManager.add_to_permanent_path_windows(path, callback)
        else:
            return PathManager.add_to_permanent_path_unix(path, callback)
    
    @staticmethod
    def check_and_fix_path(tool: str, callback: Callable[[str, str], None]) -> bool:
        """
        Check if a tool is accessible, and if not, try to find it and add to PATH.
        Returns True if tool is now accessible.
        """
        # First check if already in PATH
        if shutil.which(tool):
            return True
        
        callback(f"Tool '{tool}' not found in PATH, searching common locations...", 'info')
        
        # Search common installation paths
        found_path = PathManager.find_tool_in_common_paths(tool)
        
        if found_path:
            callback(f"Found {tool} in: {found_path}", 'success')
            
            # Add to current session
            PathManager.add_to_session_path(found_path)
            
            # Verify it works now
            if shutil.which(tool):
                callback(f"Added to current session PATH.", 'success')
                
                # Offer to add permanently
                PathManager.add_to_permanent_path(found_path, callback)
                return True
            else:
                callback(f"Added to PATH but still not accessible.", 'warning')
                return False
        else:
            callback(f"Could not find {tool} in common installation paths.", 'warning')
            return False


class ToolInstaller:
    """Handles tool installation across platforms"""
    
    # Priority order for package managers (preferred first)
    PACKAGE_MANAGER_PRIORITY = {
        'windows': ['winget', 'choco', 'scoop', 'go'],
        'darwin': ['brew', 'go'],
        'linux': ['apt', 'yum', 'dnf', 'pacman', 'go'],
    }
    
    @staticmethod
    def get_install_commands(tool: str) -> Dict[str, str]:
        """Get installation commands for a tool on current platform"""
        platform = get_platform()
        if tool in TOOL_INSTALL_INFO and platform in TOOL_INSTALL_INFO[tool]:
            return TOOL_INSTALL_INFO[tool][platform]
        return {}
    
    @staticmethod
    def get_available_package_managers() -> List[str]:
        """Get list of available package managers on the system"""
        available = []
        platform = get_platform()
        
        # Check common package managers
        managers_to_check = {
            'winget': 'winget',
            'choco': 'choco', 
            'scoop': 'scoop',
            'brew': 'brew',
            'apt': 'apt',
            'yum': 'yum',
            'dnf': 'dnf',
            'pacman': 'pacman',
            'go': 'go',
            'git': 'git',
        }
        
        for name, cmd in managers_to_check.items():
            if shutil.which(cmd):
                available.append(name)
        
        return available
    
    @staticmethod
    def get_best_install_command(tool: str) -> Optional[tuple[str, str]]:
        """
        Get the best installation command for a tool based on available package managers.
        Returns tuple of (method_name, command) or None if no suitable method found.
        """
        platform = get_platform()
        commands = ToolInstaller.get_install_commands(tool)
        available_managers = ToolInstaller.get_available_package_managers()
        
        if not commands:
            return None
        
        # Get priority order for current platform
        priority = ToolInstaller.PACKAGE_MANAGER_PRIORITY.get(platform, [])
        
        # Try to find a command using available package managers in priority order
        for manager in priority:
            if manager in available_managers:
                # Check various key formats (package_manager, choco, apt, etc.)
                for key in [manager, 'package_manager']:
                    if key in commands:
                        return (manager, commands[key])
        
        # Fallback: try any available command that's not url/instructions
        for method, command in commands.items():
            if method not in ['url', 'instructions']:
                # Check if the required tool for this method is available
                method_tool = method.split()[0] if ' ' in method else method
                if method_tool in available_managers or shutil.which(method_tool):
                    return (method, command)
        
        return None
    
    @staticmethod
    def check_package_manager() -> Optional[str]:
        """Check which package manager is available (legacy method)"""
        available = ToolInstaller.get_available_package_managers()
        platform = get_platform()
        priority = ToolInstaller.PACKAGE_MANAGER_PRIORITY.get(platform, [])
        
        for manager in priority:
            if manager in available:
                return manager
        
        return available[0] if available else None
    
    @staticmethod
    def run_install_command(command: str, callback: Callable[[str, str], None], 
                           cancel_event: Optional[threading.Event] = None) -> bool:
        """Run an installation command with output callback"""
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            
            for line in iter(process.stdout.readline, ''):
                if cancel_event and cancel_event.is_set():
                    process.terminate()
                    callback("Installation cancelled.", 'warning')
                    return False
                callback(line.rstrip(), 'output')
            
            process.wait()
            return process.returncode == 0
            
        except Exception as e:
            callback(f"Error: {str(e)}", 'error')
            return False


class QuickInstallDialog:
    """Quick auto-install dialog that starts immediately"""
    
    def __init__(self, parent, tool: str, on_complete: Callable[[], None]):
        self.parent = parent
        self.tool = tool
        self.on_complete = on_complete
        self.cancel_event = threading.Event()
        self.installing = False
        
        # Get best install command
        self.best_method = ToolInstaller.get_best_install_command(tool)
        
        # Create dialog
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"Installing {TOOLS[tool]['name']}")
        self.dialog.configure(bg=THEME['bg_primary'])
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.protocol("WM_DELETE_WINDOW", self._on_close)
        
        # Size and position
        width, height = 550, 400
        x = parent.winfo_x() + (parent.winfo_width() - width) // 2
        y = parent.winfo_y() + (parent.winfo_height() - height) // 2
        self.dialog.geometry(f"{width}x{height}+{x}+{y}")
        self.dialog.minsize(450, 300)
        
        self._create_widgets()
        
        # Auto-start installation if we have a method
        if self.best_method:
            self.dialog.after(500, self._start_install)
        else:
            self._show_manual_instructions()
    
    def _create_widgets(self):
        """Create dialog widgets"""
        main_frame = ttk.Frame(self.dialog, style='Dark.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header
        header_frame = ttk.Frame(main_frame, style='Dark.TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.title_label = tk.Label(header_frame, 
                                   text=f"⬇️ Installing {TOOLS[self.tool]['name']}...",
                                   fg=THEME['text_primary'], bg=THEME['bg_primary'],
                                   font=('Segoe UI', 14, 'bold'))
        self.title_label.pack(anchor='w')
        
        self.status_label = tk.Label(header_frame, text="Preparing installation...",
                                    fg=THEME['text_muted'], bg=THEME['bg_primary'],
                                    font=('Segoe UI', 10))
        self.status_label.pack(anchor='w', pady=(5, 0))
        
        # Method info
        if self.best_method:
            method_name, command = self.best_method
            method_frame = tk.Frame(main_frame, bg=THEME['bg_tertiary'])
            method_frame.pack(fill=tk.X, pady=(0, 15))
            
            tk.Label(method_frame, text=f"Using: {method_name.upper()}",
                    fg=THEME['info'], bg=THEME['bg_tertiary'],
                    font=('Segoe UI', 9, 'bold')).pack(anchor='w', padx=10, pady=(8, 2))
            
            tk.Label(method_frame, text=command,
                    fg=THEME['text_secondary'], bg=THEME['bg_tertiary'],
                    font=('Consolas', 9)).pack(anchor='w', padx=10, pady=(0, 8))
        
        # Progress/Output area
        output_frame = tk.Frame(main_frame, bg=THEME['bg_secondary'],
                               highlightthickness=1, highlightbackground=THEME['border'])
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame, bg='#0d0d12', fg=THEME['text_secondary'],
            font=('Consolas', 9), relief=tk.FLAT, padx=10, pady=10
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.configure(state='disabled')
        
        # Configure tags
        self.output_text.tag_configure('output', foreground=THEME['text_secondary'])
        self.output_text.tag_configure('success', foreground=THEME['success'])
        self.output_text.tag_configure('error', foreground=THEME['danger'])
        self.output_text.tag_configure('warning', foreground=THEME['warning'])
        self.output_text.tag_configure('info', foreground=THEME['info'])
        
        # Buttons
        btn_frame = ttk.Frame(main_frame, style='Dark.TFrame')
        btn_frame.pack(fill=tk.X)
        
        self.cancel_btn = ttk.Button(btn_frame, text="Cancel",
                                     style='Danger.TButton',
                                     command=self._cancel_install)
        self.cancel_btn.pack(side=tk.LEFT)
        
        self.close_btn = ttk.Button(btn_frame, text="Close",
                                    style='Secondary.TButton',
                                    command=self._close)
        self.close_btn.pack(side=tk.LEFT, padx=(10, 0))
        self.close_btn.configure(state='disabled')
        
        self.manual_btn = ttk.Button(btn_frame, text="Manual Options",
                                     style='Secondary.TButton',
                                     command=self._show_full_dialog)
        self.manual_btn.pack(side=tk.RIGHT)
    
    def _append_output(self, text: str, level: str = 'output'):
        """Append text to output"""
        self.output_text.configure(state='normal')
        self.output_text.insert(tk.END, text + '\n', level)
        self.output_text.see(tk.END)
        self.output_text.configure(state='disabled')
    
    def _start_install(self):
        """Start the installation"""
        if not self.best_method:
            return
        
        self.installing = True
        method_name, command = self.best_method
        
        self.status_label.configure(text=f"Running {method_name} installation...")
        self._append_output(f"$ {command}", 'info')
        self._append_output("-" * 50, 'output')
        
        def run_install():
            def output_callback(text, level):
                self.dialog.after(0, lambda: self._append_output(text, level))
            
            success = ToolInstaller.run_install_command(
                command, output_callback, self.cancel_event
            )
            
            self.dialog.after(0, lambda: self._install_complete(success))
        
        thread = threading.Thread(target=run_install, daemon=True)
        thread.start()
    
    def _install_complete(self, success: bool):
        """Handle installation completion"""
        self.installing = False
        self.cancel_btn.configure(state='disabled')
        self.close_btn.configure(state='normal')
        
        if success:
            # Verify installation - first check if in PATH
            if check_tool_installed(self.tool):
                self.title_label.configure(text=f"✅ {TOOLS[self.tool]['name']} Installed!")
                self.status_label.configure(text="Installation completed successfully.")
                self._append_output("\n✓ Installation successful!", 'success')
                self._append_output(f"✓ {self.tool} is now available in PATH", 'success')
            else:
                # Tool not in PATH - try to find and fix
                self._append_output("\n⚠ Installation completed but tool not found in PATH.", 'warning')
                self._append_output("Attempting to locate and add to PATH...\n", 'info')
                
                def path_callback(text, level):
                    self._append_output(text, level)
                
                # Try to find the tool and add to PATH
                if PathManager.check_and_fix_path(self.tool, path_callback):
                    self.title_label.configure(text=f"✅ {TOOLS[self.tool]['name']} Installed!")
                    self.status_label.configure(text="Installation completed. PATH updated.")
                    self._append_output(f"\n✓ {self.tool} is now accessible!", 'success')
                else:
                    self.title_label.configure(text=f"⚠️ Installation Complete")
                    self.status_label.configure(text="Installed but PATH needs manual setup.")
                    self._append_output("\n⚠ Could not automatically add to PATH.", 'warning')
                    self._append_output("You may need to manually add the installation directory to PATH.", 'output')
                    self._append_output("Or restart the application after the tool's installer updates PATH.", 'output')
        else:
            if self.cancel_event.is_set():
                self.title_label.configure(text=f"❌ Installation Cancelled")
                self.status_label.configure(text="Installation was cancelled.")
            else:
                self.title_label.configure(text=f"❌ Installation Failed")
                self.status_label.configure(text="Installation failed. Try manual options.")
                self._append_output("\n✗ Installation failed.", 'error')
                self._append_output("Try using Manual Options for alternative methods.", 'output')
    
    def _show_manual_instructions(self):
        """Show manual installation instructions when auto-install isn't available"""
        self.title_label.configure(text=f"⚠️ Manual Installation Required")
        self.status_label.configure(text="No automatic installation method available.")
        
        commands = ToolInstaller.get_install_commands(self.tool)
        
        self._append_output("No supported package manager found for auto-installation.\n", 'warning')
        
        if 'instructions' in commands:
            self._append_output("Manual Instructions:", 'info')
            self._append_output(commands['instructions'], 'output')
        
        if 'url' in commands:
            self._append_output(f"\nDownload URL: {commands['url']}", 'info')
        
        self._append_output("\nClick 'Manual Options' for more installation methods.", 'output')
        
        self.cancel_btn.configure(state='disabled')
        self.close_btn.configure(state='normal')
    
    def _cancel_install(self):
        """Cancel the installation"""
        self.cancel_event.set()
        self.status_label.configure(text="Cancelling installation...")
    
    def _show_full_dialog(self):
        """Open the full installer dialog with all options"""
        self.dialog.destroy()
        ToolInstallerDialog(self.parent, self.tool, self.on_complete)
    
    def _on_close(self):
        """Handle window close"""
        if self.installing:
            if messagebox.askyesno("Cancel Installation?", 
                                   "Installation is in progress. Cancel and close?"):
                self.cancel_event.set()
                self.dialog.after(500, self._close)
        else:
            self._close()
    
    def _close(self):
        """Close the dialog"""
        self.dialog.destroy()
        self.on_complete()


class ToolInstallerDialog:
    """Dialog window for installing tools"""
    
    def __init__(self, parent, tool: str, on_complete: Callable[[], None]):
        self.parent = parent
        self.tool = tool
        self.on_complete = on_complete
        self.install_commands = ToolInstaller.get_install_commands(tool)
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(f"Install {TOOLS[tool]['name']}")
        self.dialog.configure(bg=THEME['bg_primary'])
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Size and position
        width, height = 600, 500
        x = parent.winfo_x() + (parent.winfo_width() - width) // 2
        y = parent.winfo_y() + (parent.winfo_height() - height) // 2
        self.dialog.geometry(f"{width}x{height}+{x}+{y}")
        self.dialog.minsize(500, 400)
        
        self._create_widgets()
    
    def _create_widgets(self):
        """Create dialog widgets"""
        main_frame = ttk.Frame(self.dialog, style='Dark.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Title
        title = tk.Label(main_frame, text=f"Install {TOOLS[self.tool]['name']}",
                        fg=THEME['text_primary'], bg=THEME['bg_primary'],
                        font=('Segoe UI', 16, 'bold'))
        title.pack(anchor='w')
        
        desc = tk.Label(main_frame, text=TOOLS[self.tool]['desc'],
                       fg=THEME['text_muted'], bg=THEME['bg_primary'],
                       font=('Segoe UI', 10))
        desc.pack(anchor='w', pady=(5, 15))
        
        # Platform info
        platform = get_platform()
        platform_names = {'windows': 'Windows', 'darwin': 'macOS', 'linux': 'Linux'}
        platform_label = tk.Label(main_frame, 
                                 text=f"Detected Platform: {platform_names.get(platform, platform)}",
                                 fg=THEME['info'], bg=THEME['bg_primary'],
                                 font=('Segoe UI', 9))
        platform_label.pack(anchor='w', pady=(0, 10))
        
        # Installation options frame
        options_frame = tk.Frame(main_frame, bg=THEME['bg_secondary'],
                                highlightthickness=1, highlightbackground=THEME['border'])
        options_frame.pack(fill=tk.X, pady=(0, 15))
        
        options_title = tk.Label(options_frame, text="INSTALLATION OPTIONS",
                                fg=THEME['text_dark'], bg=THEME['bg_secondary'],
                                font=('Segoe UI', 9, 'bold'))
        options_title.pack(anchor='w', padx=15, pady=(12, 8))
        
        options_content = ttk.Frame(options_frame, style='Card.TFrame')
        options_content.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        self.selected_command = tk.StringVar()
        
        for method, command in self.install_commands.items():
            if method in ['url', 'instructions']:
                continue
            
            frame = ttk.Frame(options_content, style='Card.TFrame')
            frame.pack(fill=tk.X, pady=3)
            
            rb = tk.Radiobutton(frame, text=method.upper(), variable=self.selected_command,
                               value=command, bg=THEME['bg_secondary'], fg=THEME['text_secondary'],
                               selectcolor=THEME['bg_tertiary'], activebackground=THEME['bg_secondary'],
                               activeforeground=THEME['text_primary'], font=('Segoe UI', 10, 'bold'))
            rb.pack(side=tk.LEFT)
            
            cmd_label = tk.Label(frame, text=command, fg=THEME['text_dark'], 
                               bg=THEME['bg_secondary'], font=('Consolas', 9))
            cmd_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Manual instructions
        if 'instructions' in self.install_commands:
            inst_frame = tk.Frame(options_content, bg=THEME['bg_tertiary'])
            inst_frame.pack(fill=tk.X, pady=(10, 0))
            
            inst_label = tk.Label(inst_frame, text="Manual Installation:",
                                 fg=THEME['warning'], bg=THEME['bg_tertiary'],
                                 font=('Segoe UI', 9, 'bold'))
            inst_label.pack(anchor='w', padx=10, pady=(8, 4))
            
            inst_text = tk.Label(inst_frame, text=self.install_commands['instructions'],
                               fg=THEME['text_secondary'], bg=THEME['bg_tertiary'],
                               font=('Segoe UI', 9), wraplength=500, justify='left')
            inst_text.pack(anchor='w', padx=10, pady=(0, 8))
            
            if 'url' in self.install_commands:
                url_btn = ttk.Button(inst_frame, text="🌐 Open Download Page",
                                    style='Secondary.TButton',
                                    command=lambda: webbrowser.open(self.install_commands['url']))
                url_btn.pack(anchor='w', padx=10, pady=(0, 8))
        
        # Output terminal
        output_frame = tk.Frame(main_frame, bg=THEME['bg_secondary'],
                               highlightthickness=1, highlightbackground=THEME['border'])
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        output_title = tk.Label(output_frame, text="OUTPUT",
                               fg=THEME['text_dark'], bg=THEME['bg_secondary'],
                               font=('Segoe UI', 9, 'bold'))
        output_title.pack(anchor='w', padx=15, pady=(12, 8))
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame, bg='#0d0d12', fg=THEME['text_secondary'],
            font=('Consolas', 9), height=8, relief=tk.FLAT, padx=10, pady=10
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        self.output_text.configure(state='disabled')
        
        # Configure tags
        self.output_text.tag_configure('output', foreground=THEME['text_secondary'])
        self.output_text.tag_configure('success', foreground=THEME['success'])
        self.output_text.tag_configure('error', foreground=THEME['danger'])
        
        # Buttons
        btn_frame = ttk.Frame(main_frame, style='Dark.TFrame')
        btn_frame.pack(fill=tk.X)
        
        self.install_btn = ttk.Button(btn_frame, text="⬇️  Install Selected",
                                      style='Primary.TButton',
                                      command=self._start_install)
        self.install_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.close_btn = ttk.Button(btn_frame, text="Close",
                                    style='Secondary.TButton',
                                    command=self._close)
        self.close_btn.pack(side=tk.LEFT)
        
        self.refresh_btn = ttk.Button(btn_frame, text="🔄 Check Status",
                                      style='Secondary.TButton',
                                      command=self._check_status)
        self.refresh_btn.pack(side=tk.RIGHT)
    
    def _append_output(self, text: str, level: str = 'output'):
        """Append text to output"""
        self.output_text.configure(state='normal')
        self.output_text.insert(tk.END, text + '\n', level)
        self.output_text.see(tk.END)
        self.output_text.configure(state='disabled')
    
    def _start_install(self):
        """Start installation process"""
        command = self.selected_command.get()
        if not command:
            messagebox.showwarning("No Selection", "Please select an installation method.")
            return
        
        self.install_btn.configure(state='disabled')
        self._append_output(f"Running: {command}", 'output')
        self._append_output("-" * 50, 'output')
        
        def run_install():
            def output_callback(text, level):
                self.dialog.after(0, lambda: self._append_output(text, level))
            
            success = ToolInstaller.run_install_command(command, output_callback)
            
            def finish():
                if success:
                    self._append_output("\n✓ Installation completed!", 'success')
                else:
                    self._append_output("\n✗ Installation may have failed. Check output above.", 'error')
                self.install_btn.configure(state='normal')
                self._check_status()
            
            self.dialog.after(0, finish)
        
        thread = threading.Thread(target=run_install, daemon=True)
        thread.start()
    
    def _check_status(self):
        """Check if tool is now installed"""
        if check_tool_installed(self.tool):
            self._append_output(f"\n✓ {self.tool} is now available!", 'success')
            self.on_complete()
        else:
            self._append_output(f"\n⚠ {self.tool} not found in PATH yet.", 'error')
            self._append_output("You may need to restart the application or add the tool to your PATH.", 'output')
    
    def _close(self):
        """Close dialog"""
        self.dialog.destroy()
        self.on_complete()


# ============================================================================
# SCANNER ENGINE
# ============================================================================

class ScanEngine:
    """Handles scan execution and tool management"""
    
    def __init__(self, output_callback: Callable[[str, str], None]):
        self.output_callback = output_callback
        self.current_process: Optional[subprocess.Popen] = None
        self.cancelled = False
        self.scan_dir: Optional[Path] = None
        
    def log(self, message: str, level: str = 'info'):
        """Send log message to callback"""
        self.output_callback(message, level)
    
    def run_tool(self, tool: str, args: List[str]) -> int:
        """Run a single tool with given arguments"""
        if self.cancelled:
            return -1
        
        cmd = [tool] + args
        cmd_str = ' '.join(cmd)
        
        self.log(f"\n[*] Running {tool}...", 'info')
        self.log(f"$ {cmd_str}", 'command')
        
        try:
            # Windows compatibility: use shell=True for some tools
            shell = sys.platform == 'win32'
            
            self.current_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                cwd=str(self.scan_dir) if self.scan_dir else None,
                shell=shell if tool in ['nikto'] else False,  # Nikto may need shell on Windows
            )
            
            # Stream output
            for line in iter(self.current_process.stdout.readline, ''):
                if self.cancelled:
                    self.current_process.terminate()
                    return -1
                self.log(line.rstrip(), 'output')
            
            self.current_process.wait()
            exit_code = self.current_process.returncode
            
            if exit_code == 0:
                self.log(f"[✓] {tool} completed successfully", 'success')
            else:
                self.log(f"[✗] {tool} exited with code {exit_code}", 'error')
            
            return exit_code
            
        except FileNotFoundError:
            self.log(f"[!] {tool} not found - is it installed?", 'error')
            return -1
        except Exception as e:
            self.log(f"[!] Error running {tool}: {str(e)}", 'error')
            return -1
        finally:
            self.current_process = None
    
    def cancel(self):
        """Cancel current scan"""
        self.cancelled = True
        if self.current_process:
            try:
                self.current_process.terminate()
            except:
                pass
    
    def run_scan(self, targets: List[str], profile_key: str, tools: List[str], 
                 output_dir: Path, ports: str = '', wordlist: str = '') -> Dict:
        """Run complete scan with selected tools on multiple targets"""
        self.cancelled = False
        self.scan_dir = output_dir
        
        profile = PROFILES[profile_key]
        results = []
        
        self.log("=" * 60, 'info')
        self.log("VulnScope Vulnerability Scan", 'info')
        self.log("=" * 60, 'info')
        self.log(f"Targets: {len(targets)} target(s)", 'info')
        for i, t in enumerate(targets, 1):
            self.log(f"  [{i}] {t}", 'info')
        self.log(f"Profile: {profile.name}", 'info')
        self.log(f"Tools:   {', '.join(tools)}", 'info')
        self.log(f"Output:  {output_dir}", 'info')
        self.log("=" * 60, 'info')
        
        total_scans = len(targets) * len(tools)
        current_scan = 0
        
        for target_idx, target in enumerate(targets, 1):
            if self.cancelled:
                break
            
            safe_target = sanitize_filename(target)
            
            self.log(f"\n{'─' * 60}", 'info')
            self.log(f"Target [{target_idx}/{len(targets)}]: {target}", 'info')
            self.log(f"{'─' * 60}", 'info')
            
            for tool in tools:
                if self.cancelled:
                    break
                
                current_scan += 1
                
                if not check_tool_installed(tool):
                    self.log(f"[!] {tool} not installed - skipping", 'warning')
                    continue
                
                self.log(f"\n[{current_scan}/{total_scans}] Running {tool} on {target}...", 'info')
                
                args = self._build_args(tool, target, profile, safe_target, ports, wordlist)
                exit_code = self.run_tool(tool, args)
                
                results.append({
                    'tool': tool,
                    'target': target,
                    'exit_code': exit_code,
                    'output_file': self._get_output_filename(tool, safe_target),
                })
        
        if self.cancelled:
            self.log("\n[!] Scan cancelled by user", 'warning')
            return {'status': 'cancelled', 'results': results, 'targets': targets}
        
        self.log("\n" + "=" * 60, 'success')
        self.log(f"Scan Complete! ({len(targets)} target(s), {len(tools)} tool(s))", 'success')
        self.log("=" * 60, 'success')
        
        return {'status': 'complete', 'results': results, 'targets': targets}
    
    def _build_args(self, tool: str, target: str, profile: ScanProfile, 
                    safe_target: str, ports: str, wordlist: str) -> List[str]:
        """Build command arguments for a tool"""
        args = []
        
        if tool == 'nmap':
            args.extend(profile.nmap)
            if ports:
                args.extend(['-p', ports])
            args.extend(['-oA', f'nmap_{safe_target}'])
            args.append(target)
            
        elif tool == 'nuclei':
            args.extend(['-u', target])
            args.extend(profile.nuclei)
            args.extend(['-o', f'nuclei_{safe_target}.json', '-j'])
            
        elif tool == 'nikto':
            args.extend(['-h', target])
            args.extend(profile.nikto)
            args.extend(['-o', f'nikto_{safe_target}.html', '-Format', 'htm'])
            
        elif tool == 'gobuster':
            args.extend(['dir', '-u', target])
            args.extend(profile.gobuster)
            wl = wordlist or self._find_wordlist()
            if wl:
                args.extend(['-w', wl])
            args.extend(['-o', f'gobuster_{safe_target}.txt'])
            
        elif tool == 'masscan':
            args.append(target)
            args.extend(['-p', ports or '1-65535'])
            args.extend(profile.masscan)
            args.extend(['-oJ', f'masscan_{safe_target}.json'])
        
        return args
    
    def _get_output_filename(self, tool: str, safe_target: str) -> str:
        """Get output filename for a tool"""
        extensions = {
            'nmap': f'nmap_{safe_target}.xml',
            'nuclei': f'nuclei_{safe_target}.json',
            'nikto': f'nikto_{safe_target}.html',
            'gobuster': f'gobuster_{safe_target}.txt',
            'masscan': f'masscan_{safe_target}.json',
        }
        return extensions.get(tool, f'{tool}_{safe_target}.txt')
    
    def _find_wordlist(self) -> str:
        """Find a wordlist on the system"""
        common_paths = [
            # Linux paths
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            # Windows paths
            'C:\\wordlists\\common.txt',
            'C:\\Tools\\wordlists\\common.txt',
            'C:\\SecLists\\Discovery\\Web-Content\\common.txt',
            os.path.expanduser('~\\wordlists\\common.txt'),
            os.path.expanduser('~\\SecLists\\Discovery\\Web-Content\\common.txt'),
        ]
        for path in common_paths:
            if os.path.exists(path):
                return path
        return ''

# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generates HTML reports from scan results - handles multiple tool outputs"""
    
    @staticmethod
    def safe_read_file(filepath: Path, encoding: str = 'utf-8') -> str:
        """Safely read a file with fallback encodings"""
        encodings = [encoding, 'utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        
        for enc in encodings:
            try:
                with open(filepath, 'r', encoding=enc, errors='replace') as f:
                    return f.read()
            except (UnicodeDecodeError, UnicodeError):
                continue
            except Exception:
                break
        
        # Last resort: read as bytes and decode with replacement
        try:
            with open(filepath, 'rb') as f:
                return f.read().decode('utf-8', errors='replace')
        except Exception:
            return ''
    
    @staticmethod
    def safe_string(text: str) -> str:
        """Ensure string is safe for HTML output"""
        if not text:
            return ''
        # Remove or replace problematic characters
        return ''.join(char if ord(char) < 65536 and char.isprintable() or char in '\n\r\t' else '?' for char in str(text))
    
    @staticmethod
    def parse_nuclei_results(scan_dir: Path) -> List[Dict]:
        """Parse Nuclei JSON output"""
        findings = []
        
        for file in scan_dir.glob('nuclei_*.json'):
            try:
                content = ReportGenerator.safe_read_file(file)
                for line in content.splitlines():
                    if line.strip():
                        try:
                            data = json.loads(line)
                            findings.append({
                                'tool': 'Nuclei',
                                'severity': data.get('info', {}).get('severity', 'info'),
                                'title': ReportGenerator.safe_string(data.get('info', {}).get('name', 'Unknown')),
                                'description': ReportGenerator.safe_string(data.get('info', {}).get('description', '')),
                                'host': ReportGenerator.safe_string(data.get('host', '')),
                                'matched': ReportGenerator.safe_string(data.get('matched-at', '')),
                                'template': data.get('template-id', ''),
                            })
                        except json.JSONDecodeError:
                            continue
            except Exception:
                continue
        
        return findings
    
    @staticmethod
    def parse_nmap_results(scan_dir: Path) -> List[Dict]:
        """Parse Nmap XML output"""
        findings = []
        
        for file in scan_dir.glob('nmap_*.xml'):
            try:
                content = ReportGenerator.safe_read_file(file)
                
                # Simple XML parsing without external dependencies
                # Find all open ports
                import re
                
                # Extract host info
                hosts = re.findall(r'<host[^>]*>.*?</host>', content, re.DOTALL)
                
                for host_block in hosts:
                    # Get IP address
                    ip_match = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', host_block)
                    ip = ip_match.group(1) if ip_match else 'Unknown'
                    
                    # Get hostname
                    hostname_match = re.search(r'<hostname name="([^"]+)"', host_block)
                    hostname = hostname_match.group(1) if hostname_match else ''
                    
                    # Find open ports
                    ports = re.findall(r'<port protocol="([^"]+)" portid="(\d+)"[^>]*>.*?<state state="open"[^>]*/?>.*?(?:<service name="([^"]*)"[^>]*(?:product="([^"]*)")?[^>]*(?:version="([^"]*)")?)?.*?</port>', host_block, re.DOTALL)
                    
                    for port_info in ports:
                        protocol = port_info[0] if len(port_info) > 0 else 'tcp'
                        port = port_info[1] if len(port_info) > 1 else '?'
                        service = port_info[2] if len(port_info) > 2 else ''
                        product = port_info[3] if len(port_info) > 3 else ''
                        version = port_info[4] if len(port_info) > 4 else ''
                        
                        service_info = f"{service}"
                        if product:
                            service_info += f" ({product}"
                            if version:
                                service_info += f" {version}"
                            service_info += ")"
                        
                        findings.append({
                            'tool': 'Nmap',
                            'severity': 'info',
                            'title': f"Open Port: {port}/{protocol}",
                            'description': ReportGenerator.safe_string(service_info) or 'Service detected',
                            'host': ReportGenerator.safe_string(f"{ip}" + (f" ({hostname})" if hostname else '')),
                            'matched': '',
                        })
                    
                    # Find script outputs (vulnerabilities)
                    scripts = re.findall(r'<script id="([^"]+)"[^>]*output="([^"]*)"', host_block)
                    for script_id, output in scripts:
                        if 'vuln' in script_id.lower() or 'VULNERABLE' in output:
                            findings.append({
                                'tool': 'Nmap',
                                'severity': 'high' if 'VULNERABLE' in output else 'medium',
                                'title': ReportGenerator.safe_string(f"Script: {script_id}"),
                                'description': ReportGenerator.safe_string(output[:500]),
                                'host': ReportGenerator.safe_string(ip),
                                'matched': '',
                            })
                            
            except Exception:
                continue
        
        return findings
    
    @staticmethod
    def parse_masscan_results(scan_dir: Path) -> List[Dict]:
        """Parse Masscan JSON output"""
        findings = []
        
        for file in scan_dir.glob('masscan_*.json'):
            try:
                content = ReportGenerator.safe_read_file(file)
                # Masscan JSON can be malformed (trailing comma), try to fix
                content = content.strip()
                if content.endswith(',]'):
                    content = content[:-2] + ']'
                if content.endswith(','):
                    content = content[:-1]
                
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        for item in data:
                            if 'ports' in item:
                                ip = item.get('ip', 'Unknown')
                                for port_info in item.get('ports', []):
                                    port = port_info.get('port', '?')
                                    proto = port_info.get('proto', 'tcp')
                                    
                                    findings.append({
                                        'tool': 'Masscan',
                                        'severity': 'info',
                                        'title': f"Open Port: {port}/{proto}",
                                        'description': 'Port discovered by Masscan',
                                        'host': ReportGenerator.safe_string(str(ip)),
                                        'matched': '',
                                    })
                except json.JSONDecodeError:
                    pass
            except Exception:
                continue
        
        return findings
    
    @staticmethod
    def parse_gobuster_results(scan_dir: Path) -> List[Dict]:
        """Parse Gobuster text output"""
        findings = []
        
        for file in scan_dir.glob('gobuster_*.txt'):
            try:
                content = ReportGenerator.safe_read_file(file)
                
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('='):
                        continue
                    
                    # Parse gobuster output format: /path (Status: 200) [Size: 1234]
                    import re
                    match = re.match(r'^(/[^\s]*)\s*\(Status:\s*(\d+)\)', line)
                    if match:
                        path = match.group(1)
                        status = match.group(2)
                        
                        # Determine severity based on status code
                        severity = 'info'
                        if status in ['200', '201', '301', '302']:
                            severity = 'low'
                        if status == '403':
                            severity = 'info'
                        
                        findings.append({
                            'tool': 'Gobuster',
                            'severity': severity,
                            'title': f"Directory/File Found: {path}",
                            'description': f"HTTP Status: {status}",
                            'host': '',
                            'matched': ReportGenerator.safe_string(path),
                        })
            except Exception:
                continue
        
        return findings
    
    @staticmethod
    def parse_nikto_results(scan_dir: Path) -> List[Dict]:
        """Parse Nikto HTML or text output"""
        findings = []
        
        # Try HTML files first
        for file in scan_dir.glob('nikto_*.html'):
            try:
                content = ReportGenerator.safe_read_file(file)
                
                # Extract findings from HTML - look for vulnerability entries
                import re
                
                # Nikto HTML format varies, try to extract meaningful items
                items = re.findall(r'<td[^>]*>([^<]*(?:OSVDB|CVE|vulnerability|found)[^<]*)</td>', content, re.IGNORECASE)
                
                for item in items[:50]:  # Limit to prevent huge reports
                    item = item.strip()
                    if len(item) > 10:
                        severity = 'info'
                        if 'vulnerability' in item.lower() or 'CVE' in item:
                            severity = 'medium'
                        if 'critical' in item.lower() or 'remote code' in item.lower():
                            severity = 'high'
                        
                        findings.append({
                            'tool': 'Nikto',
                            'severity': severity,
                            'title': ReportGenerator.safe_string(item[:100]),
                            'description': ReportGenerator.safe_string(item),
                            'host': '',
                            'matched': '',
                        })
            except Exception:
                continue
        
        # Also try text files
        for file in scan_dir.glob('nikto_*.txt'):
            try:
                content = ReportGenerator.safe_read_file(file)
                
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith('+') and ':' in line:
                        # Nikto text format: + OSVDB-1234: /path: Description
                        severity = 'info'
                        if 'OSVDB' in line or 'CVE' in line:
                            severity = 'medium'
                        
                        findings.append({
                            'tool': 'Nikto',
                            'severity': severity,
                            'title': ReportGenerator.safe_string(line[:100]),
                            'description': ReportGenerator.safe_string(line),
                            'host': '',
                            'matched': '',
                        })
            except Exception:
                continue
        
        return findings
    
    @staticmethod
    def generate(scan_dir: Path, target: str, profile: str, tools: List[str]) -> Path:
        """Generate HTML report from scan results"""
        all_findings = []
        
        # Parse all tool outputs
        all_findings.extend(ReportGenerator.parse_nuclei_results(scan_dir))
        all_findings.extend(ReportGenerator.parse_nmap_results(scan_dir))
        all_findings.extend(ReportGenerator.parse_masscan_results(scan_dir))
        all_findings.extend(ReportGenerator.parse_gobuster_results(scan_dir))
        all_findings.extend(ReportGenerator.parse_nikto_results(scan_dir))
        
        # Count severities
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in all_findings:
            sev = f.get('severity', 'info').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Generate HTML
        html = ReportGenerator._generate_html(target, profile, tools, all_findings, severity_counts)
        
        report_path = scan_dir / 'report.html'
        with open(report_path, 'w', encoding='utf-8', errors='replace') as f:
            f.write(html)
        
        return report_path
    
    @staticmethod
    def _generate_html(target: str, profile: str, tools: List[str], 
                       findings: List[Dict], severity_counts: Dict) -> str:
        """Generate HTML content"""
        import html as html_module
        
        # Safely escape target
        safe_target = html_module.escape(ReportGenerator.safe_string(target))
        safe_profile = html_module.escape(ReportGenerator.safe_string(profile))
        
        severity_colors = {
            'critical': '#ef4444',
            'high': '#f59e0b',
            'medium': '#eab308',
            'low': '#06b6d4',
            'info': '#6366f1',
        }
        
        findings_html = ''
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            sev_findings = [f for f in findings if f.get('severity', 'info').lower() == sev]
            if sev_findings:
                findings_html += f'<h3 style="color: {severity_colors[sev]}; margin: 24px 0 16px;">{sev.upper()} ({len(sev_findings)})</h3>'
                for f in sev_findings:
                    title = html_module.escape(ReportGenerator.safe_string(f.get('title', 'Unknown')))
                    desc = html_module.escape(ReportGenerator.safe_string(f.get('description', '')[:500]))
                    host = html_module.escape(ReportGenerator.safe_string(f.get('host', '')))
                    tool = html_module.escape(ReportGenerator.safe_string(f.get('tool', 'Unknown')))
                    
                    findings_html += f'''
                    <div style="background: rgba(255,255,255,0.02); border-left: 3px solid {severity_colors.get(sev, '#6366f1')}; 
                                padding: 16px; margin-bottom: 12px; border-radius: 0 8px 8px 0;">
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                            <span style="background: rgba(99,102,241,0.2); color: #6366f1; padding: 4px 8px; 
                                        border-radius: 4px; font-size: 11px;">{tool}</span>
                            <strong>{title}</strong>
                        </div>
                        <p style="margin: 8px 0; color: #a1a1aa;">{desc}</p>
                        {f'<code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; font-size: 12px;">{host}</code>' if host else ''}
                    </div>
                    '''
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>VulnScope Report - {safe_target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: #0a0a0f; color: #e4e4e7; padding: 40px; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ font-size: 28px; margin-bottom: 8px; }}
        .subtitle {{ color: #71717a; margin-bottom: 32px; font-size: 14px; }}
        .meta {{ background: rgba(255,255,255,0.02); border-radius: 12px; padding: 20px; margin-bottom: 32px; }}
        .meta-row {{ display: flex; margin-bottom: 8px; }}
        .meta-label {{ color: #71717a; width: 120px; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 40px; }}
        .summary-card {{ background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.1);
                        border-radius: 12px; padding: 20px; text-align: center; }}
        .summary-card .count {{ font-size: 32px; font-weight: 700; }}
        .summary-card .label {{ font-size: 12px; color: #71717a; text-transform: uppercase; margin-top: 4px; }}
        h2 {{ font-size: 20px; margin: 32px 0 16px; }}
        @media print {{ body {{ background: white; color: black; }} }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ VulnScope Security Report</h1>
        <p class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="meta">
            <div class="meta-row"><span class="meta-label">Target:</span><span>{safe_target}</span></div>
            <div class="meta-row"><span class="meta-label">Profile:</span><span>{safe_profile}</span></div>
            <div class="meta-row"><span class="meta-label">Tools:</span><span>{', '.join(tools)}</span></div>
            <div class="meta-row"><span class="meta-label">Total Findings:</span><span>{len(findings)}</span></div>
        </div>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-card"><div class="count" style="color: #ef4444">{severity_counts['critical']}</div><div class="label">Critical</div></div>
            <div class="summary-card"><div class="count" style="color: #f59e0b">{severity_counts['high']}</div><div class="label">High</div></div>
            <div class="summary-card"><div class="count" style="color: #eab308">{severity_counts['medium']}</div><div class="label">Medium</div></div>
            <div class="summary-card"><div class="count" style="color: #06b6d4">{severity_counts['low']}</div><div class="label">Low</div></div>
            <div class="summary-card"><div class="count" style="color: #6366f1">{severity_counts['info']}</div><div class="label">Info</div></div>
        </div>
        
        <h2>Findings</h2>
        {findings_html or '<p style="color: #71717a;">No vulnerability findings detected.</p>'}
    </div>
</body>
</html>'''

# ============================================================================
# MAIN GUI APPLICATION
# ============================================================================

class VulnScopeApp:
    """Main application class"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("VulnScope - Blue Team Vulnerability Scanner")
        self.root.configure(bg=THEME['bg_primary'])
        
        # State
        self.selected_profile = tk.StringVar(value='accuracy')
        self.selected_tools: Dict[str, tk.BooleanVar] = {}
        self.available_tools = get_available_tools()
        self.scan_thread: Optional[threading.Thread] = None
        self.scan_engine: Optional[ScanEngine] = None
        self.output_queue = queue.Queue()
        self.current_scan_dir: Optional[Path] = None
        self.current_targets: List[str] = []  # Store targets for current scan
        
        # Output directory
        self.output_base = Path.home() / 'VulnScope_Scans'
        self.output_base.mkdir(exist_ok=True)
        
        # Setup UI
        self._setup_styles()
        self._create_widgets()
        self._start_output_consumer()
        
        # Auto-size window after widgets are created
        self.root.update_idletasks()
        self._auto_size_window()
        
        # Check PATH for tools on startup (runs after UI is ready)
        self.root.after(1000, self._check_tools_path_on_startup)
        
    def _auto_size_window(self):
        """Auto-size window based on content with reasonable bounds"""
        # Get the required size
        self.root.update_idletasks()
        
        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Calculate preferred size (content-based with padding)
        req_width = self.root.winfo_reqwidth()
        req_height = self.root.winfo_reqheight()
        
        # Set reasonable bounds
        min_width, min_height = 900, 650
        max_width = int(screen_width * 0.9)
        max_height = int(screen_height * 0.85)
        
        # Calculate final dimensions
        width = max(min_width, min(req_width + 40, max_width))
        height = max(min_height, min(req_height + 40, max_height))
        
        # Center on screen
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        self.root.minsize(min_width, min_height)
        
        # Allow resizing
        self.root.resizable(True, True)
    
    def _check_tools_path_on_startup(self):
        """Check if installed tools are accessible in PATH on startup"""
        tools_fixed = []
        tools_found_not_in_path = []
        
        for tool in TOOLS.keys():
            # Skip if already in PATH
            if check_tool_installed(tool):
                continue
            
            # Try to find the tool in common installation paths
            found_path = PathManager.find_tool_in_common_paths(tool)
            if found_path:
                tools_found_not_in_path.append((tool, found_path))
        
        # If we found tools that aren't in PATH, offer to fix
        if tools_found_not_in_path:
            tool_names = [t[0] for t in tools_found_not_in_path]
            message = (
                f"Found {len(tools_found_not_in_path)} tool(s) installed but not in PATH:\n"
                f"{', '.join(tool_names)}\n\n"
                "Would you like to add them to PATH now?"
            )
            
            if messagebox.askyesno("Tools Found", message):
                for tool, path in tools_found_not_in_path:
                    # Add to session PATH
                    PathManager.add_to_session_path(path)
                    
                    # Verify it works
                    if check_tool_installed(tool):
                        tools_fixed.append(tool)
                        
                        # Add to permanent PATH silently
                        def silent_callback(text, level):
                            pass  # Suppress output
                        PathManager.add_to_permanent_path(path, silent_callback)
                
                if tools_fixed:
                    # Refresh the UI
                    self._refresh_tool_status()
                    messagebox.showinfo(
                        "PATH Updated", 
                        f"Added {len(tools_fixed)} tool(s) to PATH:\n{', '.join(tools_fixed)}\n\n"
                        "The PATH has also been updated permanently."
                    )
        
    def _setup_styles(self):
        """Setup ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('.',
            background=THEME['bg_primary'],
            foreground=THEME['text_primary'],
            fieldbackground=THEME['bg_input'],
            bordercolor=THEME['border'],
            darkcolor=THEME['bg_secondary'],
            lightcolor=THEME['bg_tertiary'],
            troughcolor=THEME['bg_secondary'],
            selectbackground=THEME['accent'],
            selectforeground=THEME['text_primary'],
        )
        
        # Frame styles
        style.configure('Card.TFrame', background=THEME['bg_secondary'])
        style.configure('Dark.TFrame', background=THEME['bg_primary'])
        
        # Label styles
        style.configure('Title.TLabel',
            background=THEME['bg_primary'],
            foreground=THEME['text_primary'],
            font=('Segoe UI', 24, 'bold')
        )
        style.configure('Subtitle.TLabel',
            background=THEME['bg_primary'],
            foreground=THEME['text_muted'],
            font=('Segoe UI', 10)
        )
        style.configure('Section.TLabel',
            background=THEME['bg_secondary'],
            foreground=THEME['text_muted'],
            font=('Segoe UI', 9, 'bold')
        )
        style.configure('Card.TLabel',
            background=THEME['bg_secondary'],
            foreground=THEME['text_secondary'],
            font=('Segoe UI', 10)
        )
        
        # Button styles
        style.configure('Primary.TButton',
            background=THEME['accent'],
            foreground='white',
            font=('Segoe UI', 11, 'bold'),
            padding=(20, 12),
        )
        style.map('Primary.TButton',
            background=[('active', THEME['accent_hover']), ('disabled', THEME['bg_tertiary'])],
            foreground=[('disabled', THEME['text_dark'])]
        )
        
        style.configure('Secondary.TButton',
            background=THEME['bg_tertiary'],
            foreground=THEME['text_secondary'],
            font=('Segoe UI', 10),
            padding=(12, 8),
        )
        style.map('Secondary.TButton',
            background=[('active', THEME['border'])]
        )
        
        style.configure('Danger.TButton',
            background=THEME['danger'],
            foreground='white',
            font=('Segoe UI', 11, 'bold'),
            padding=(20, 12),
        )
        
        style.configure('Install.TButton',
            background=THEME['warning'],
            foreground='white',
            font=('Segoe UI', 9),
            padding=(8, 4),
        )
        style.map('Install.TButton',
            background=[('active', '#d97706')]
        )
        
        # Entry style
        style.configure('TEntry',
            fieldbackground=THEME['bg_input'],
            foreground=THEME['text_primary'],
            insertcolor=THEME['text_primary'],
            padding=10,
        )
        
        # Checkbutton style
        style.configure('Tool.TCheckbutton',
            background=THEME['bg_secondary'],
            foreground=THEME['text_secondary'],
            font=('Segoe UI', 10),
        )
        style.map('Tool.TCheckbutton',
            background=[('active', THEME['bg_secondary'])]
        )
        
        # Radiobutton style
        style.configure('Profile.TRadiobutton',
            background=THEME['bg_tertiary'],
            foreground=THEME['text_secondary'],
            font=('Segoe UI', 10),
            padding=10,
        )
        style.map('Profile.TRadiobutton',
            background=[('selected', THEME['bg_secondary']), ('active', THEME['bg_tertiary'])]
        )

    def _create_widgets(self):
        """Create all UI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root, style='Dark.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header
        self._create_header(main_frame)
        
        # Content area (two columns)
        content = ttk.Frame(main_frame, style='Dark.TFrame')
        content.pack(fill=tk.BOTH, expand=True, pady=(20, 0))
        
        # Left column - Configuration
        left_col = ttk.Frame(content, style='Dark.TFrame')
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 10))
        
        self._create_target_panel(left_col)
        self._create_profile_panel(left_col)
        self._create_tools_panel(left_col)
        self._create_action_buttons(left_col)
        
        # Right column - Output
        right_col = ttk.Frame(content, style='Dark.TFrame')
        right_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        self._create_output_panel(right_col)
        self._create_results_panel(right_col)
    
    def _create_header(self, parent):
        """Create header with title and status"""
        header = ttk.Frame(parent, style='Dark.TFrame')
        header.pack(fill=tk.X)
        
        # Title
        title_frame = ttk.Frame(header, style='Dark.TFrame')
        title_frame.pack(side=tk.LEFT)
        
        ttk.Label(title_frame, text="🛡️ VulnScope", style='Title.TLabel').pack(anchor='w')
        ttk.Label(title_frame, text="Blue Team Vulnerability Scanner", style='Subtitle.TLabel').pack(anchor='w')
        
        # Tools status
        status_frame = ttk.Frame(header, style='Dark.TFrame')
        status_frame.pack(side=tk.RIGHT)
        
        ttk.Label(status_frame, text="Tools Status:", style='Subtitle.TLabel').pack(side=tk.LEFT, padx=(0, 10))
        
        for tool, available in self.available_tools.items():
            color = THEME['success'] if available else THEME['danger']
            label = tk.Label(status_frame, text=f"● {tool}", 
                           fg=color, bg=THEME['bg_primary'],
                           font=('Segoe UI', 9))
            label.pack(side=tk.LEFT, padx=5)
    
    def _create_target_panel(self, parent):
        """Create target input panel"""
        frame = self._create_card(parent, "TARGET(S)")
        
        # Hint label
        hint = tk.Label(frame, text="Separate multiple targets with commas",
                       fg=THEME['text_dark'], bg=THEME['bg_secondary'],
                       font=('Segoe UI', 8))
        hint.pack(anchor='w', pady=(0, 5))
        
        # Target input
        self.target_entry = ttk.Entry(frame, font=('Consolas', 11), width=40)
        self.target_entry.pack(fill=tk.X, pady=(0, 10))
        self.target_entry.insert(0, "")
        self.target_entry.configure(foreground=THEME['text_primary'])
        
        # Placeholder behavior
        placeholder = "192.168.1.1, 10.0.0.1, example.com (comma-separated)"
        self.target_entry.insert(0, placeholder)
        self.target_entry.configure(foreground=THEME['text_dark'])
        
        def on_focus_in(e):
            if self.target_entry.get() == placeholder:
                self.target_entry.delete(0, tk.END)
                self.target_entry.configure(foreground=THEME['text_primary'])
        
        def on_focus_out(e):
            if not self.target_entry.get():
                self.target_entry.insert(0, placeholder)
                self.target_entry.configure(foreground=THEME['text_dark'])
        
        self.target_entry.bind('<FocusIn>', on_focus_in)
        self.target_entry.bind('<FocusOut>', on_focus_out)
        
        # Ports input
        ports_frame = ttk.Frame(frame, style='Card.TFrame')
        ports_frame.pack(fill=tk.X)
        
        ttk.Label(ports_frame, text="Ports (optional):", style='Card.TLabel').pack(anchor='w')
        self.ports_entry = ttk.Entry(ports_frame, font=('Consolas', 10), width=30)
        self.ports_entry.pack(fill=tk.X, pady=(5, 0))
    
    def _create_profile_panel(self, parent):
        """Create scan profile selection panel"""
        frame = self._create_card(parent, "SCAN PROFILE")
        
        # Create profile buttons in a grid
        profiles_grid = ttk.Frame(frame, style='Card.TFrame')
        profiles_grid.pack(fill=tk.X)
        
        row = 0
        col = 0
        for key, profile in PROFILES.items():
            btn_frame = tk.Frame(profiles_grid, bg=THEME['bg_tertiary'], 
                               highlightthickness=2, highlightbackground=THEME['border'])
            btn_frame.grid(row=row, column=col, padx=5, pady=5, sticky='nsew')
            
            # Make it look selected when chosen
            def make_select_handler(k, f):
                def handler(e=None):
                    self.selected_profile.set(k)
                    self._update_profile_selection()
                return handler
            
            btn_frame.bind('<Button-1>', make_select_handler(key, btn_frame))
            
            # Profile name
            name_label = tk.Label(btn_frame, text=profile.name, 
                                 fg=profile.color, bg=THEME['bg_tertiary'],
                                 font=('Segoe UI', 10, 'bold'), cursor='hand2')
            name_label.pack(padx=10, pady=(8, 2))
            name_label.bind('<Button-1>', make_select_handler(key, btn_frame))
            
            # Profile description
            desc_label = tk.Label(btn_frame, text=profile.description,
                                 fg=THEME['text_dark'], bg=THEME['bg_tertiary'],
                                 font=('Segoe UI', 8), cursor='hand2', wraplength=120)
            desc_label.pack(padx=10, pady=(0, 8))
            desc_label.bind('<Button-1>', make_select_handler(key, btn_frame))
            
            # Store reference
            btn_frame.profile_key = key
            
            col += 1
            if col > 2:
                col = 0
                row += 1
        
        # Configure grid weights
        for i in range(3):
            profiles_grid.columnconfigure(i, weight=1)
        
        self.profile_frames = profiles_grid.winfo_children()
        self._update_profile_selection()
    
    def _update_profile_selection(self):
        """Update profile button appearance based on selection"""
        selected = self.selected_profile.get()
        for frame in self.profile_frames:
            if hasattr(frame, 'profile_key'):
                if frame.profile_key == selected:
                    color = PROFILES[frame.profile_key].color
                    frame.configure(highlightbackground=color, highlightthickness=2)
                else:
                    frame.configure(highlightbackground=THEME['border'], highlightthickness=1)
    
    def _create_tools_panel(self, parent):
        """Create tools selection panel with install buttons"""
        frame = self._create_card(parent, "TOOLS")
        
        tools_frame = ttk.Frame(frame, style='Card.TFrame')
        tools_frame.pack(fill=tk.X)
        
        self.tool_widgets = {}  # Store references for updating
        
        for tool, info in TOOLS.items():
            var = tk.BooleanVar(value=tool in ['nmap', 'nuclei'])
            self.selected_tools[tool] = var
            
            available = self.available_tools.get(tool, False)
            
            tool_frame = ttk.Frame(tools_frame, style='Card.TFrame')
            tool_frame.pack(fill=tk.X, pady=2)
            
            cb = ttk.Checkbutton(tool_frame, text=f"{info['name']}", 
                                variable=var, style='Tool.TCheckbutton')
            cb.pack(side=tk.LEFT)
            
            # Store widget references
            self.tool_widgets[tool] = {
                'frame': tool_frame,
                'checkbox': cb,
                'var': var,
            }
            
            if not available:
                cb.configure(state='disabled')
                var.set(False)
                
                # Status label
                status = tk.Label(tool_frame, text="(not installed)", 
                                fg=THEME['danger'], bg=THEME['bg_secondary'],
                                font=('Segoe UI', 8))
                status.pack(side=tk.LEFT, padx=(5, 0))
                self.tool_widgets[tool]['status'] = status
                
                # Install button
                def make_install_handler(t):
                    return lambda: self._open_install_dialog(t)
                
                install_btn = ttk.Button(tool_frame, text="Install",
                                        style='Install.TButton',
                                        command=make_install_handler(tool))
                install_btn.pack(side=tk.RIGHT, padx=(5, 0))
                self.tool_widgets[tool]['install_btn'] = install_btn
            else:
                # Installed indicator
                status = tk.Label(tool_frame, text="✓", 
                                fg=THEME['success'], bg=THEME['bg_secondary'],
                                font=('Segoe UI', 9))
                status.pack(side=tk.LEFT, padx=(5, 0))
                self.tool_widgets[tool]['status'] = status
            
            desc = tk.Label(tool_frame, text=f"- {info['desc']}", 
                          fg=THEME['text_dark'], bg=THEME['bg_secondary'],
                          font=('Segoe UI', 8))
            desc.pack(side=tk.LEFT, padx=(10, 0))
            self.tool_widgets[tool]['desc'] = desc
    
    def _open_install_dialog(self, tool: str):
        """Open the quick auto-install dialog"""
        def on_complete():
            self._refresh_tool_status()
        
        # Use QuickInstallDialog for automatic installation
        QuickInstallDialog(self.root, tool, on_complete)
    
    def _refresh_tool_status(self):
        """Refresh tool availability status"""
        self.available_tools = get_available_tools()
        
        for tool, widgets in self.tool_widgets.items():
            available = self.available_tools.get(tool, False)
            
            if available:
                # Enable checkbox
                widgets['checkbox'].configure(state='normal')
                
                # Update status label
                if 'status' in widgets:
                    widgets['status'].configure(text="✓", fg=THEME['success'])
                
                # Remove install button if it exists
                if 'install_btn' in widgets:
                    widgets['install_btn'].destroy()
                    del widgets['install_btn']
            else:
                widgets['checkbox'].configure(state='disabled')
                widgets['var'].set(False)
    
    def _create_action_buttons(self, parent):
        """Create scan/cancel buttons"""
        btn_frame = ttk.Frame(parent, style='Dark.TFrame')
        btn_frame.pack(fill=tk.X, pady=(15, 0))
        
        self.scan_btn = ttk.Button(btn_frame, text="▶  Start Scan", 
                                   style='Primary.TButton',
                                   command=self._start_scan)
        self.scan_btn.pack(fill=tk.X, pady=(0, 5))
        
        self.cancel_btn = ttk.Button(btn_frame, text="■  Cancel Scan",
                                     style='Danger.TButton',
                                     command=self._cancel_scan)
        self.cancel_btn.pack(fill=tk.X)
        self.cancel_btn.pack_forget()  # Hide initially
    
    def _create_output_panel(self, parent):
        """Create terminal output panel"""
        frame = self._create_card(parent, "LIVE OUTPUT", expand=True)
        
        # Terminal-like text widget
        self.output_text = scrolledtext.ScrolledText(
            frame,
            bg='#0d0d12',
            fg=THEME['text_secondary'],
            font=('Consolas', 10),
            insertbackground=THEME['text_primary'],
            selectbackground=THEME['accent'],
            relief=tk.FLAT,
            padx=10,
            pady=10,
            wrap=tk.WORD,
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.configure(state='disabled')
        
        # Configure tags for colored output
        self.output_text.tag_configure('info', foreground=THEME['accent'])
        self.output_text.tag_configure('command', foreground=THEME['info'])
        self.output_text.tag_configure('output', foreground=THEME['text_secondary'])
        self.output_text.tag_configure('success', foreground=THEME['success'])
        self.output_text.tag_configure('error', foreground=THEME['danger'])
        self.output_text.tag_configure('warning', foreground=THEME['warning'])
    
    def _create_results_panel(self, parent):
        """Create results/files panel"""
        self.results_frame = self._create_card(parent, "OUTPUT FILES", height=150)
        self.results_frame.pack_forget()  # Hide initially
        
        # Results list
        self.results_list = ttk.Frame(self.results_frame, style='Card.TFrame')
        self.results_list.pack(fill=tk.BOTH, expand=True)
        
        # Buttons
        btn_frame = ttk.Frame(self.results_frame, style='Card.TFrame')
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.report_btn = ttk.Button(btn_frame, text="📄 Generate Report",
                                     style='Secondary.TButton',
                                     command=self._generate_report)
        self.report_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.folder_btn = ttk.Button(btn_frame, text="📁 Open Folder",
                                     style='Secondary.TButton',
                                     command=self._open_folder)
        self.folder_btn.pack(side=tk.LEFT)
    
    def _create_card(self, parent, title, height=None, expand=False):
        """Create a card-style frame"""
        outer = ttk.Frame(parent, style='Dark.TFrame')
        outer.pack(fill=tk.BOTH, expand=expand, pady=(0, 15))
        
        card = tk.Frame(outer, bg=THEME['bg_secondary'], 
                       highlightthickness=1, highlightbackground=THEME['border'])
        card.pack(fill=tk.BOTH, expand=expand)
        
        if height:
            card.configure(height=height)
        
        # Title
        title_label = tk.Label(card, text=title, 
                              fg=THEME['text_dark'], bg=THEME['bg_secondary'],
                              font=('Segoe UI', 9, 'bold'))
        title_label.pack(anchor='w', padx=15, pady=(12, 8))
        
        # Content frame
        content = ttk.Frame(card, style='Card.TFrame')
        content.pack(fill=tk.BOTH, expand=expand, padx=15, pady=(0, 15))
        
        return content
    
    def _append_output(self, text: str, level: str = 'output'):
        """Append text to output terminal"""
        self.output_text.configure(state='normal')
        self.output_text.insert(tk.END, text + '\n', level)
        self.output_text.see(tk.END)
        self.output_text.configure(state='disabled')
    
    def _clear_output(self):
        """Clear output terminal"""
        self.output_text.configure(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.configure(state='disabled')
    
    def _start_output_consumer(self):
        """Start thread to consume output queue"""
        def consume():
            while True:
                try:
                    text, level = self.output_queue.get(timeout=0.1)
                    self.root.after(0, lambda t=text, l=level: self._append_output(t, l))
                except queue.Empty:
                    pass
        
        thread = threading.Thread(target=consume, daemon=True)
        thread.start()
    
    def _output_callback(self, text: str, level: str):
        """Callback for scan engine to send output"""
        self.output_queue.put((text, level))
    
    def _start_scan(self):
        """Start vulnerability scan"""
        # Get and validate target input
        target_input = self.target_entry.get().strip()
        placeholder = "192.168.1.1, 10.0.0.1, example.com (comma-separated)"
        if target_input == placeholder:
            target_input = ""
        
        valid, error = validate_target(target_input)
        if not valid:
            messagebox.showerror("Invalid Target", error)
            return
        
        # Parse multiple targets
        targets = parse_targets(target_input)
        if not targets:
            messagebox.showerror("Invalid Target", "No valid targets provided")
            return
        
        # Validate each target individually
        for target in targets:
            valid, error = validate_single_target(target)
            if not valid:
                messagebox.showerror("Invalid Target", f"Invalid target '{target}': {error}")
                return
        
        # Get selected tools
        tools = [t for t, var in self.selected_tools.items() if var.get()]
        if not tools:
            messagebox.showerror("No Tools Selected", "Please select at least one tool")
            return
        
        # Check if any selected tools are available
        available_selected = [t for t in tools if self.available_tools.get(t, False)]
        if not available_selected:
            messagebox.showerror("Tools Not Available", 
                               "None of the selected tools are installed")
            return
        
        # Create output directory (use first target for naming, or "multi" if multiple)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if len(targets) == 1:
            safe_name = sanitize_filename(targets[0])
        else:
            safe_name = f"multi_{len(targets)}_targets"
        self.current_scan_dir = self.output_base / f"scan_{safe_name}_{timestamp}"
        self.current_scan_dir.mkdir(parents=True, exist_ok=True)
        
        # Save targets list to file for reference
        with open(self.current_scan_dir / 'targets.txt', 'w') as f:
            f.write('\n'.join(targets))
        
        # Update UI
        self._clear_output()
        self.scan_btn.pack_forget()
        self.cancel_btn.pack(fill=tk.X)
        self.results_frame.pack_forget()
        self.target_entry.configure(state='disabled')
        self.ports_entry.configure(state='disabled')
        
        # Create scan engine
        self.scan_engine = ScanEngine(self._output_callback)
        
        # Get options
        profile = self.selected_profile.get()
        ports = self.ports_entry.get().strip()
        
        # Store targets for report generation
        self.current_targets = targets
        
        # Start scan in thread
        def run_scan():
            try:
                result = self.scan_engine.run_scan(
                    targets=targets,
                    profile_key=profile,
                    tools=available_selected,
                    output_dir=self.current_scan_dir,
                    ports=ports,
                )
                self.root.after(0, lambda: self._scan_complete(result))
            except Exception as e:
                self.root.after(0, lambda: self._scan_error(str(e)))
        
        self.scan_thread = threading.Thread(target=run_scan, daemon=True)
        self.scan_thread.start()
    
    def _cancel_scan(self):
        """Cancel running scan"""
        if self.scan_engine:
            self.scan_engine.cancel()
    
    def _scan_complete(self, result):
        """Handle scan completion"""
        # Update UI
        self.cancel_btn.pack_forget()
        self.scan_btn.pack(fill=tk.X, pady=(0, 5))
        self.target_entry.configure(state='normal')
        self.ports_entry.configure(state='normal')
        
        # Show results panel
        if self.current_scan_dir and self.current_scan_dir.exists():
            self._update_results_panel()
            self.results_frame.pack(fill=tk.X, pady=(15, 0))
    
    def _scan_error(self, error: str):
        """Handle scan error"""
        self._append_output(f"[!] Scan error: {error}", 'error')
        self._scan_complete({'status': 'error'})
    
    def _update_results_panel(self):
        """Update results panel with output files"""
        # Clear existing
        for widget in self.results_list.winfo_children():
            widget.destroy()
        
        if not self.current_scan_dir:
            return
        
        # List files
        for file in sorted(self.current_scan_dir.iterdir()):
            if file.is_file():
                file_frame = ttk.Frame(self.results_list, style='Card.TFrame')
                file_frame.pack(fill=tk.X, pady=2)
                
                # File name
                name = tk.Label(file_frame, text=f"📄 {file.name}",
                              fg=THEME['text_secondary'], bg=THEME['bg_secondary'],
                              font=('Consolas', 9))
                name.pack(side=tk.LEFT)
                
                # File size
                size = tk.Label(file_frame, text=f"({format_file_size(file.stat().st_size)})",
                              fg=THEME['text_dark'], bg=THEME['bg_secondary'],
                              font=('Segoe UI', 8))
                size.pack(side=tk.LEFT, padx=(10, 0))
                
                # Open button
                def make_open_handler(f):
                    return lambda: self._open_file(f)
                
                open_btn = ttk.Button(file_frame, text="Open",
                                     style='Secondary.TButton',
                                     command=make_open_handler(file))
                open_btn.pack(side=tk.RIGHT)
    
    def _generate_report(self):
        """Generate HTML report"""
        if not self.current_scan_dir:
            return
        
        try:
            # Use stored targets or parse from entry
            if hasattr(self, 'current_targets') and self.current_targets:
                targets = self.current_targets
                target_str = ', '.join(targets) if len(targets) <= 3 else f"{len(targets)} targets"
            else:
                target_str = self.target_entry.get().strip()
            
            profile = self.selected_profile.get()
            tools = [t for t, var in self.selected_tools.items() if var.get()]
            
            report_path = ReportGenerator.generate(
                self.current_scan_dir, target_str, profile, tools
            )
            
            self._append_output(f"\n[✓] Report generated: {report_path}", 'success')
            self._update_results_panel()
            
            # Open in browser
            webbrowser.open(f'file://{report_path}')
            
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report: {str(e)}")
    
    def _open_folder(self):
        """Open scan output folder"""
        if self.current_scan_dir and self.current_scan_dir.exists():
            if sys.platform == 'win32':
                os.startfile(self.current_scan_dir)
            elif sys.platform == 'darwin':
                subprocess.run(['open', self.current_scan_dir])
            else:
                subprocess.run(['xdg-open', self.current_scan_dir])
    
    def _open_file(self, file_path: Path):
        """Open a file with default application"""
        if sys.platform == 'win32':
            os.startfile(file_path)
        elif sys.platform == 'darwin':
            subprocess.run(['open', file_path])
        else:
            subprocess.run(['xdg-open', file_path])
    
    def run(self):
        """Run the application"""
        self.root.mainloop()

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required")
        sys.exit(1)
    
    # Create and run app
    app = VulnScopeApp()
    app.run()

if __name__ == '__main__':
    main()
