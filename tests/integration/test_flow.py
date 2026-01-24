from typer.testing import CliRunner
from veritensor.cli.main import app

runner = CliRunner()

def test_cli_scan_clean(clean_model_path):
    result = runner.invoke(app, ["scan", str(clean_model_path)])
    assert result.exit_code == 0
    assert "Scan Passed" in result.stdout

def test_cli_scan_infected(infected_pickle_path):
    # Should fail by default
    result = runner.invoke(app, ["scan", str(infected_pickle_path)])
    assert result.exit_code == 1
    assert "BLOCKING DEPLOYMENT" in result.stdout

def test_cli_ignore_malware(infected_pickle_path):
    # Should pass with warning
    result = runner.invoke(app, ["scan", str(infected_pickle_path), "--ignore-malware"])
    assert result.exit_code == 0
    assert "MALWARE/INTEGRITY RISKS DETECTED (Ignored by user)" in result.stdout

def test_cli_force_deprecated(infected_pickle_path):
    # Should pass but maybe warn about deprecation (optional, logic handles it as ignore all)
    result = runner.invoke(app, ["scan", str(infected_pickle_path), "--force"])
    assert result.exit_code == 0
    assert "RISKS DETECTED" in result.stdout

# Note: To test license ignoring specifically, we would need a file with a bad license.
# Since malware_gen creates pickles (no license metadata), we rely on unit tests for that logic,
# or we could mock the reader in a more complex integration test.
