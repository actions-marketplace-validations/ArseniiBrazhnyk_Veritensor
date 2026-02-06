import pytest
from typer.testing import CliRunner
from unittest.mock import MagicMock
from pathlib import Path
from veritensor.cli.main import app
from veritensor.core.types import ScanResult

runner = CliRunner()

@pytest.fixture
def mock_executor(mocker):
    """
    Mock ProcessPoolExecutor to avoid spawning real processes during tests.
    It intercepts the 'submit' call and returns a mock Future.
    """
    mock_pool = mocker.patch("concurrent.futures.ProcessPoolExecutor")
    mock_instance = mock_pool.return_value
    mock_instance.__enter__.return_value = mock_instance
    return mock_instance

@pytest.fixture
def mock_worker(mocker):
    """Mocks the worker function so we don't actually scan files."""
    return mocker.patch("veritensor.cli.main.scan_worker")

def test_scan_local_file_clean(tmp_path, mock_executor, mock_worker):
    # 1. Create a dummy file
    f = tmp_path / "model.pkl"
    f.write_text("fake pickle content")

    # 2. Setup Mock Result (Clean)
    fake_result = ScanResult(str(f), status="PASS")
    fake_result.file_hash = "sha256:12345"
    
    # Setup the Future object that Executor returns
    mock_future = MagicMock()
    mock_future.result.return_value = fake_result
    
    # When executor.submit is called, return our fake future
    mock_executor.submit.return_value = mock_future

    # 3. Run CLI
    result = runner.invoke(app, ["scan", str(f)])

    # 4. Assertions
    assert result.exit_code == 0
    assert "Scan Passed" in result.stdout
    assert "Starting scan with" in result.stdout

def test_scan_malware_blocking(tmp_path, mock_executor, mock_worker):
    # 1. Dummy file
    f = tmp_path / "evil.pkl"
    f.write_text("malware")

    # 2. Setup Mock Result (Infected)
    fake_result = ScanResult(str(f), status="FAIL")
    fake_result.add_threat("CRITICAL: RCE Detected")
    
    mock_future = MagicMock()
    mock_future.result.return_value = fake_result
    mock_executor.submit.return_value = mock_future

    # 3. Run CLI
    result = runner.invoke(app, ["scan", str(f)])

    # 4. Assertions
    assert result.exit_code == 1
    assert "BLOCKING DEPLOYMENT" in result.stdout
    assert "Malware/Integrity" in result.stdout

def test_scan_ignore_malware(tmp_path, mock_executor):
    # Test the new flag --ignore-malware (replaced --force)
    f = tmp_path / "evil.pkl"
    f.write_text("malware")

    fake_result = ScanResult(str(f), status="FAIL")
    fake_result.add_threat("CRITICAL: RCE Detected")
    
    mock_future = MagicMock()
    mock_future.result.return_value = fake_result
    
    # Mocking executor submit
    mock_executor.submit.return_value = mock_future
    # Important: We also need to make sure the loop over futures works. 
    # Since we mocked ProcessPoolExecutor, we assume logic is correct.

    # 3. Run CLI with --ignore-malware
    result = runner.invoke(app, ["scan", str(f), "--ignore-malware"])

    # 4. Assertions
    assert result.exit_code == 0  # Should pass now
    assert "Scan Passed" in result.stdout
    assert "MALWARE/INTEGRITY RISKS DETECTED (Ignored by user)" in result.stdout
