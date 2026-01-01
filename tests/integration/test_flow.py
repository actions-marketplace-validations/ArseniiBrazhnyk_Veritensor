from typer.testing import CliRunner
from veritensor.cli.main import app

runner = CliRunner()

def test_cli_scan_clean(clean_model_path):
    # 1. Запуск сканера на чистом файле
    # ВАЖНО: Добавили "scan" первым аргументом
    result = runner.invoke(app, ["scan", str(clean_model_path)])
    
    # Отладка: если упадет, покажет вывод
    print(result.stdout) 
    
    # 2. Ожидаем успех (Exit Code 0)
    assert result.exit_code == 0
    assert "Scan Passed" in result.stdout

def test_cli_scan_infected(infected_pickle_path):
    # 1. Запуск на вирусе
    # ВАЖНО: Добавили "scan"
    result = runner.invoke(app, ["scan", str(infected_pickle_path)])
    
    print(result.stdout)

    # 2. Ожидаем провал (Exit Code 1)
    assert result.exit_code == 1
    assert "BLOCKING DEPLOYMENT" in result.stdout
    # Проверяем наличие одной из ключевых фраз угрозы
    assert "CRITICAL" in result.stdout or "UNSAFE_IMPORT" in result.stdout

def test_cli_break_glass(infected_pickle_path):
    # 1. Запуск на вирусе, но с флагом --force
    # ВАЖНО: Добавили "scan"
    result = runner.invoke(app, ["scan", str(infected_pickle_path), "--force"])
    
    print(result.stdout)

    # 2. Ожидаем успех (Exit Code 0), но с предупреждением
    assert result.exit_code == 0
    assert "Break-glass mode enabled" in result.stdout
