# Copyright 2025 Veritensor Security
# Logic adapted from ModelScan (Apache 2.0 License)
#
# This engine scans Keras models (.h5, .keras) for "Lambda" layers.
# Lambda layers can contain serialized Python bytecode, leading to RCE.
# Patched against Zip Bombs (DoS) using SafeZipReader.

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Union

# Security: Use SafeZipReader to prevent Zip Bombs
from veritensor.core.utils import SafeZipReader

logger = logging.getLogger(__name__)

# Constants
HDF5_MAGIC = b'\x89HDF\r\n\x1a\n'
PK_MAGIC = b'PK\x03\x04'

try:
    import h5py
    H5PY_AVAILABLE = True
except ImportError:
    H5PY_AVAILABLE = False

def scan_keras_file(file_path: Path) -> List[str]:
    """
    Main entry point for Keras scanning.
    Detects format (Zip/Keras v3 or H5/Legacy) and scans architecture config.
    """
    threats = []
    try:
        # Check Magic Bytes to determine format reliably
        if _is_zip_magic(file_path):
            threats.extend(_scan_keras_zip(file_path))
        elif _is_hdf5_magic(file_path):
            if H5PY_AVAILABLE:
                threats.extend(_scan_keras_h5(file_path))
            else:
                threats.append("WARNING: h5py missing, cannot scan legacy .h5 file. Install 'h5py'.")
    except Exception as e:
        logger.error(f"Failed to scan Keras file {file_path}: {e}")
        threats.append(f"Scan Error: {str(e)}")
        
    return threats

def _is_zip_magic(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == PK_MAGIC
    except OSError:
        return False

def _is_hdf5_magic(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(8) == HDF5_MAGIC
    except OSError:
        return False

def _scan_keras_zip(file_path: Path) -> List[str]:
    """
    Scans modern .keras files (Zip archive containing config.json).
    Uses SafeZipReader for DoS protection.
    """
    threats = []
    try:
        with SafeZipReader(file_path) as z:
            for filename in z.namelist():
                # Keras v3 stores config in config.json
                # SavedModel stores it in slightly different paths, but usually at root or under assets
                if filename.endswith("config.json") or filename == "model_config":
                    content = z.read(filename)
                    if not content: 
                        continue # Empty file or blocked by SafeZipReader
                    
                    try:
                        config = json.loads(content)
                        threats.extend(_analyze_model_config(config))
                    except json.JSONDecodeError:
                        pass
    except Exception as e:
        # SafeZipReader might raise ValueError on zip bombs
        logger.warning(f"Keras Zip scan warning: {e}")
    
    return threats

def _scan_keras_h5(file_path: Path) -> List[str]:
    """
    Scans legacy .h5 files using h5py.
    """
    threats = []
    try:
        with h5py.File(file_path, "r") as f:
            if "model_config" in f.attrs:
                config_str = f.attrs["model_config"]
                # H5 attributes can be bytes or string
                if isinstance(config_str, bytes):
                    config_str = config_str.decode("utf-8", errors="ignore")
                
                try:
                    config_data = json.loads(config_str)
                    threats.extend(_analyze_model_config(config_data))
                except json.JSONDecodeError:
                    pass
    except Exception as e:
        logger.warning(f"Error reading Keras H5 {file_path}: {e}")
    return threats

def _analyze_model_config(config: Union[Dict[str, Any], List]) -> List[str]:
    """
    Recursively searches for 'Lambda' layers in the model architecture.
    """
    threats = []
    
    # Keras config is usually a dict with "config" key, or a list of layers
    to_scan = [config]
    
    while to_scan:
        item = to_scan.pop()
        
        if isinstance(item, dict):
            # Check for Lambda Layer
            if item.get("class_name") == "Lambda":
                threats.append("CRITICAL: Keras Lambda layer detected (RCE Risk)")
            
            # Recurse into values
            for value in item.values():
                if isinstance(value, (dict, list)):
                    to_scan.append(value)
                    
        elif isinstance(item, list):
            # Recurse into list items
            for element in item:
                if isinstance(element, (dict, list)):
                    to_scan.append(element)

    return threats
