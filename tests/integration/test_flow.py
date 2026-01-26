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


@patch("requests.get")
def test_cli_update(mock_get, tmp_path):
    """
    It is testing the update command with a simulated response from GitHub.
    """
    # Fake the server's response
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = """
version: "2099.01.01"
unsafe_globals:
  CRITICAL:
    os: "*"
"""
    mock_get.return_value = mock_response

    # Fake the user's home directory so as not to trash the real system.
    # "When the code asks for Path.home(), return the temporary test folder"
    with patch("pathlib.Path.home", return_value=tmp_path):
        # Run the command
        result = runner.invoke(app, ["update"])
        
        # Checking for success
        assert result.exit_code == 0
        assert "Successfully updated" in result.stdout
        
        # Check that the file was actually created.
        saved_file = tmp_path / ".veritensor" / "signatures.yaml"
        assert saved_file.exists()
        assert "2099.01.01" in saved_file.read_text()


# Note: To test license ignoring specifically, we would need a file with a bad license.
# Since malware_gen creates pickles (no license metadata), we rely on unit tests for that logic,
# or we could mock the reader in a more complex integration test.
