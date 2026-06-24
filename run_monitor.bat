@echo off
REM 启动邮件到达/连接监控。第一次用前请先把 config.example.ini 复制为 config.ini 并填好。
chcp 65001 >nul
cd /d "%~dp0"
if not exist config.ini (
  echo [!] 没找到 config.ini，请先把 config.example.ini 复制为 config.ini 并填写。
  pause
  exit /b 1
)
echo [*] 正在启动监控，按 Ctrl+C 可停止...
python src\imap_monitor.py
pause
