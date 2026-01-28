# Copyright 2025 Veritensor Security Apache 2.0
# RAG Scanner: Detects Prompt Injections in text files.

import logging
from typing import List
from pathlib import Path
from veritensor.engines.static.rules import SignatureLoader, is_match

logger = logging.getLogger(__name__)

# Supported text formats for RAG scanning
TEXT_EXTENSIONS = {
    # Documentation & Markup
    ".txt", ".md", ".markdown", ".rst", ".adoc", ".asciidoc", 
    ".tex", ".org", ".wiki",
    
    # Data & Configs
    ".json", ".csv", ".xml", ".yaml", ".yml", ".toml", 
    ".ini", ".cfg", ".conf", ".env", ".properties", ".editorconfig",
    ".tsv", ".ndjson", ".jsonl", ".ldjson",
    
    # Source Code (Scripts)
    ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp",
    ".rs", ".go", ".rb", ".php", ".pl", ".lua",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".sql",
    
    # Infrastructure & DevOps
    ".dockerfile", ".tf", ".tfvars", ".k8s", ".helm", ".tpl",
    ".gitignore", ".gitattributes",
    
    # Logs
    ".log", ".out", ".err"
}

def scan_text_file(file_path: Path) -> List[str]:
    threats = []
    signatures = SignatureLoader.get_prompt_injections()
    
    try:
        # Errors='ignore' allows us to scan files that are mostly text 
        # but might have some binary garbage (like logs)
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                # Limit line length to prevent Regex DoS on minified files
                if len(line) > 4096: 
                    line = line[:4096] 
                
                if is_match(line, signatures):
                    for pattern in signatures:
                        if is_match(line, [pattern]):
                            threats.append(f"HIGH: Prompt Injection detected (line {i+1}): '{pattern}'")
                            return threats # Fail fast
                            
    except Exception as e:
        logger.warning(f"Failed to scan text file {file_path}: {e}")
        
    return threats
