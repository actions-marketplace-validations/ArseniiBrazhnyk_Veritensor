import pytest
from unittest.mock import patch, MagicMock
from aegis.integrations.cosign import sign_container

@patch("aegis.integrations.cosign.subprocess.run")
@patch("aegis.integrations.cosign.is_cosign_available", return_value=True)
@patch("pathlib.Path.exists", return_value=True) # Имитируем наличие ключа
def test_sign_container_success(mock_exists, mock_avail, mock_run):
    # Настраиваем мок, чтобы он вернул "Успех"
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "Signed successfully"
    mock_run.return_value = mock_proc

    result = sign_container("my-image:v1", "key.pem")
    
    assert result is True
    # Проверяем, что cosign был вызван с правильными флагами
    args = mock_run.call_args[0][0]
    assert "cosign" in args
    assert "sign" in args
    assert "--tlog-upload=false" in args # Приватность по умолчанию
