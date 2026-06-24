@echo off
REM 运行全部自动化测试（纯标准库，无需联网、无需真实邮箱）。
chcp 65001 >nul
cd /d "%~dp0"
python -m unittest discover -s tests -p "test_*.py" -v
pause
