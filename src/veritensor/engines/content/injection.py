# Copyright 2025 Veritensor Security Apache 2.0
# RAG Scanner: Detects Prompt Injections in text files.

import logging
from typing import List
from pathlib import Path
from veritensor.engines.static.rules import SignatureLoader, is_match

logger = logging.getLogger(__name__)

# Supported text formats for RAG scanning
TEXT_EXTENSIONS = {".txt", ".md", ".json", ".csv", ".xml", ".yaml", ".yml"}

def scan_text_file(file_path: Path) -> List[str]:
    """
    Scans a text file for Prompt Injection patterns.
    """
    threats = []
    try:
        # Limit read size to 5MB to prevent DoS
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(5 * 1024 * 1024)
            
        signatures = SignatureLoader.get_prompt_injections()
        
        if is_match(content, signatures):
            # Find specific matches for reporting
            for pattern in signatures:
                if is_match(content, [pattern]):
                    threats.append(f"HIGH: Prompt Injection detected: '{pattern}'")
                    
    except Exception as e:
        logger.warning(f"Failed to scan text file {file_path}: {e}")
        
    return threats
