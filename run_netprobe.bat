@echo off
REM 启动网络层探测（测到邮件服务器的连接延迟/丢包）。可与监控同时运行。
chcp 65001 >nul
cd /d "%~dp0"
if not exist config.ini (
  echo [!] 没找到 config.ini，请先把 config.example.ini 复制为 config.ini 并填写。
  pause
  exit /b 1
)
echo [*] 正在探测网络，按 Ctrl+C 可停止...
python src\net_probe.py --interval 60
pause
