# Copyright 2025 Veritensor Security
# Data adapted from ModelScan (Apache 2.0 License)
#
# This module defines the "Blocklist" of unsafe Python globals.
# It categorizes threats by severity (CRITICAL = RCE, HIGH = Network/Exfiltration).

import re
import logging
import yaml
from pathlib import Path
from typing import Dict, List, Union, Optional, Any

logger = logging.getLogger(__name__)

# Wildcard to indicate the entire module is unsafe
ALL_FUNCTIONS = "*"

# --- Default Signatures (Fallback if file is missing) ---
DEFAULT_UNSAFE_GLOBALS = {
    "CRITICAL": {
        "__builtin__": ["eval", "compile", "getattr", "apply", "exec", "open", "breakpoint", "__import__"],
        "builtins": ["eval", "compile", "getattr", "apply", "exec", "open", "breakpoint", "__import__"],
        "runpy": ALL_FUNCTIONS,
        "os": ALL_FUNCTIONS,
        "nt": ALL_FUNCTIONS,      # Alias for 'os' on Windows
        "posix": ALL_FUNCTIONS,   # Alias for 'os' on Linux
        "socket": ALL_FUNCTIONS,  # Network access
        "subprocess": ALL_FUNCTIONS,
        "sys": ALL_FUNCTIONS,     # Interpreter manipulation
        "operator": ["attrgetter"], # Gadget chain
        "pty": ALL_FUNCTIONS,
        "pickle": ALL_FUNCTIONS,
        "_pickle": ALL_FUNCTIONS,
        "bdb": ALL_FUNCTIONS,
        "pdb": ALL_FUNCTIONS,
        "shutil": ALL_FUNCTIONS,
        "asyncio": ALL_FUNCTIONS,
        "marshal": ALL_FUNCTIONS,
    },
    "HIGH": {
        "webbrowser": ALL_FUNCTIONS,
        "httplib": ALL_FUNCTIONS,
        "requests.api": ALL_FUNCTIONS,
        "aiohttp.client": ALL_FUNCTIONS,
        "urllib": ALL_FUNCTIONS,
        "urllib2": ALL_FUNCTIONS,
    },
    "MEDIUM": {},
    "LOW": {},
}

# Default restricted patterns (Simple strings)
DEFAULT_RESTRICTED_LICENSES = [
    "cc-by-nc",
    "agpl",
    "non-commercial",
    "research-only",
]

class SignatureLoader:
    """
    Loads security signatures. 
    Prioritizes 'signatures.yaml' if present, falls back to hardcoded defaults.
    """
    _instance = None
    _globals = DEFAULT_UNSAFE_GLOBALS

    @classmethod
    def get_globals(cls) -> Dict[str, Dict[str, Any]]:
        if cls._instance is None:
            cls._instance = cls()
            cls._instance._load()
        return cls._instance._globals

    def _load(self):
        # Look for signatures.yaml in the same directory as this file
        sig_path = Path(__file__).parent / "signatures.yaml"
        if sig_path.exists():
            try:
                with open(sig_path, "r") as f:
                    data = yaml.safe_load(f)
                    if data and "unsafe_globals" in data:
                        self._globals = data["unsafe_globals"]
                        logger.debug(f"Loaded signatures from {sig_path}")
            except Exception as e:
                logger.warning(f"Failed to load signatures.yaml, using defaults: {e}")

def get_severity(module: str, name: str) -> Optional[str]:
    """
    Checks a module.function pair against the blocklist.
    """
    unsafe_globals = SignatureLoader.get_globals()

    # Check CRITICAL first, then HIGH, etc.
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        rules = unsafe_globals.get(severity, {})
        
        if module in rules:
            allowed_list = rules[module]
            
            # If the rule is "*", the whole module is blacklisted
            if allowed_list == ALL_FUNCTIONS:
                return severity
            
            # Otherwise, check specific function names
            if isinstance(allowed_list, list) and name in allowed_list:
                return severity

    return None

def is_critical_threat(module: str, name: str) -> bool:
    """Helper to quickly check if an import represents an RCE risk."""
    return get_severity(module, name) == "CRITICAL"

# --- Regex & Matching Logic ---

def is_match(value: str, patterns: List[str]) -> bool:
    """
    Hybrid matcher:
    1. If rule starts with 'regex:' or 'pattern:' -> treat as Regular Expression.
    2. Otherwise -> treat as simple substring match (case-insensitive).
    """
    if not value:
        return False
        
    for pattern in patterns:
        # --- Mode 1: Regex ---
        if pattern.startswith("regex:") or pattern.startswith("pattern:"):
            # Strip prefix (e.g. "regex:^meta-.*")
            regex_str = pattern.split(":", 1)[1]
            try:
                if re.search(regex_str, value, re.IGNORECASE):
                    return True
            except re.error:
                logger.warning(f"Invalid regex pattern in config: {regex_str}")
                continue
        
        # --- Mode 2: Simple Substring (Default) ---
        else:
            if pattern.lower() in value.lower():
                return True
            
    return False

def is_license_restricted(license_str: str, custom_list: List[str] = None) -> bool:
    """Checks if a license string matches restricted rules."""
    patterns = custom_list if custom_list else DEFAULT_RESTRICTED_LICENSES
    return is_match(license_str, patterns)
