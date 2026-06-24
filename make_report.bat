@echo off
REM 把采集到的日志汇总成一份可外发的报告（只含统计，不含邮件内容）。
chcp 65001 >nul
cd /d "%~dp0"
python src\report.py
pause
