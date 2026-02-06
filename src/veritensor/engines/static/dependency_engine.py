# Copyright 2026 Veritensor Security Apache 2.0
# Dependency Scanner: Detects Typosquatting, Malware, and CVEs (via OSV.dev)

import logging
import re
import requests
from pathlib import Path
from typing import List, Set, Dict, Optional

logger = logging.getLogger(__name__)

# --- Configuration ---
OSV_API_URL = "https://api.osv.dev/v1/querybatch"

# --- Known Malware DB (MVP) ---
KNOWN_MALICIOUS = {
    "tourch", "pytorch-nightly-cpu", "request", "colorama-color", 
    "discord-py-slash-command", "py-cord-slash", "huggingface-cli-tool"
}

# Popular packages for Typosquatting checks
POPULAR_PACKAGES = {
    "torch", "tensorflow", "requests", "numpy", "pandas", "scikit-learn",
    "transformers", "huggingface-hub", "flask", "django", "fastapi", "boto3"
}

def scan_dependencies(file_path: Path) -> List[str]:
    """
    Scans dependency files for:
    1. Typosquatting (fake packages)
    2. Known Malware (names)
    3. Vulnerabilities (CVEs via OSV.dev API)
    """
    threats = []
    filename = file_path.name.lower()
    
    try:
        # Dictionary: { "package_name": "version" or None }
        dependencies = {}
        
        # 1. Parse File
        if filename == "requirements.txt":
            dependencies = _parse_requirements(file_path)
        elif filename == "pyproject.toml":
            dependencies = _parse_toml(file_path)
        # TODO: Add poetry.lock / Pipfile.lock support for better precision
        
        if not dependencies:
            return []

        # 2. Static Analysis (Typos & Malware)
        for pkg_name in dependencies.keys():
            pkg_lower = pkg_name.lower()
            
            # A. Known Malware
            if pkg_lower in KNOWN_MALICIOUS:
                threats.append(f"CRITICAL: Known malicious package detected: '{pkg_name}'")
            
            # B. Typosquatting
            for popular in POPULAR_PACKAGES:
                if pkg_lower != popular and _is_typo(pkg_lower, popular):
                    threats.append(f"HIGH: Potential Typosquatting: '{pkg_name}' looks like '{popular}'")

        # 3. Dynamic Analysis (OSV.dev CVE Check)
        # Only check packages with pinned versions to avoid false positives
        pinned_packages = {k: v for k, v in dependencies.items() if v}
        
        if pinned_packages:
            cve_threats = _check_osv_batch(pinned_packages)
            threats.extend(cve_threats)

    except Exception as e:
        logger.warning(f"Dependency scan failed for {file_path}: {e}")
        threats.append(f"WARNING: Dependency Scan Error: {str(e)}")

    return threats

def _check_osv_batch(packages: Dict[str, str]) -> List[str]:
    """
    Queries OSV.dev API in a single batch request.
    """
    threats = []
    payload = {"queries": []}
    
    # Prepare payload
    pkg_list = [] # Keep order to map results back
    for name, version in packages.items():
        payload["queries"].append({
            "package": {"name": name, "ecosystem": "PyPI"},
            "version": version
        })
        pkg_list.append((name, version))
        
    try:
        # Timeout is short to not block the scan if API is down
        response = requests.post(OSV_API_URL, json=payload, timeout=3)
        
        if response.status_code != 200:
            logger.debug(f"OSV API Error: {response.status_code}")
            return []
            
        results = response.json().get("results", [])
        
        for i, res in enumerate(results):
            if "vulns" in res:
                pkg_name, pkg_ver = pkg_list[i]
                for vuln in res["vulns"]:
                    vuln_id = vuln.get("id", "UNKNOWN")
                    summary = vuln.get("summary", "Vulnerability detected")
                    # OSV doesn't always provide severity score in summary, defaulting to HIGH
                    threats.append(f"HIGH: CVE Detected in {pkg_name}=={pkg_ver}: [{vuln_id}] {summary}")
                    
    except Exception as e:
        logger.debug(f"OSV Check failed (offline?): {e}")
        
    return threats

def _parse_requirements(path: Path) -> Dict[str, Optional[str]]:
    """Extracts package names and pinned versions (==)."""
    deps = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"): continue
            
            # Simple parsing for "package==1.2.3"
            # Ignores complex markers like "; python_version < '3.8'" for MVP
            parts = line.split("==")
            if len(parts) >= 2:
                name = parts[0].strip()
                # Clean version (remove comments or markers)
                version = parts[1].split("#")[0].split(";")[0].strip()
                deps[name] = version
            else:
                # Handle >=, ~= etc by just taking the name
                name = re.split(r'[><=~;]', line)[0].strip()
                if name:
                    deps[name] = None
    return deps

def _parse_toml(path: Path) -> Dict[str, Optional[str]]:
    """Simple regex parser for pyproject.toml (MVP)."""
    deps = {}
    try:
        content = path.read_text(encoding="utf-8")
        # Matches: name = "version"
        # Very basic, won't catch complex inline tables
        matches = re.findall(r'^\s*([a-zA-Z0-9_-]+)\s*=\s*"(.*?)"', content, re.MULTILINE)
        
        for name, version in matches:
            if name not in ["python", "version", "name", "description"]:
                # If version starts with ^ or ~, OSV might not handle it perfectly in simple query,
                # but we pass it anyway. Ideally we need a semantic version resolver.
                # For MVP, we strip caret/tilde to check "exact" match if possible, or pass as is.
                clean_ver = version.lstrip("^~=")
                deps[name] = clean_ver
    except Exception:
        pass
    return deps

def _is_typo(s1: str, s2: str) -> bool:
    """
    Robust Levenshtein Distance (D=1) check.
    Detects substitutions (turch), deletions (toch), and insertions (ttorch).
    """
    n, m = len(s1), len(s2)
    if abs(n - m) > 1: return False

    if n == m:
        # Case: Substitution (torch -> turch)
        return sum(1 for a, b in zip(s1, s2) if a != b) == 1
    
    # Case: Insertion/Deletion (torch -> toch)
    if n > m: s1, s2 = s2, s1 # s2 is always longer
    
    i = j = diffs = 0
    while i < len(s1) and j < len(s2):
        if s1[i] != s2[j]:
            diffs += 1
            j += 1 # Skip extra char in longer string
            if diffs > 1: return False
        else:
            i += 1
            j += 1
    return True
