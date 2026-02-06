import pytest
from veritensor.engines.static.dependency_engine import scan_dependencies, _is_typo

def test_is_typo_logic():
    """Validates the core edit distance algorithm."""
    # Substitution
    assert _is_typo("turch", "torch") is True
    # Deletion
    assert _is_typo("toch", "torch") is True
    # Insertion
    assert _is_typo("ttorch", "torch") is True
    # Too many differences
    assert _is_typo("tor", "torch") is False
    # Identical strings
    assert _is_typo("torch", "torch") is False

def test_scan_requirements_malware(tmp_path):
    """Checks detection of known malicious entries in requirements.txt."""
    f = tmp_path / "requirements.txt"
    f.write_text("tourch==1.0\nnumpy\n")
    threats = scan_dependencies(f)
    assert any("Known malicious" in t and "tourch" in t for t in threats)

def test_scan_requirements_typo(tmp_path):
    """Checks typosquatting detection for popular packages."""
    f = tmp_path / "requirements.txt"
    f.write_text("pndas>=1.0\n")
    threats = scan_dependencies(f)
    assert any("Potential Typosquatting" in t and "pandas" in t for t in threats)

def test_scan_toml_dependencies(tmp_path):
    """Checks parsing and detection within pyproject.toml."""
    f = tmp_path / "pyproject.toml"
    f.write_text("""
    [project.dependencies]
    torch = ">=2.0"
    reqests = "0.1"
    """)
    threats = scan_dependencies(f)
    assert any("Potential Typosquatting" in t and "requests" in t for t in threats)
