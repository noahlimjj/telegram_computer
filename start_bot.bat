@echo off
title Antigravity Telegram Workstation Daemon
cd /d "%~dp0"
set SSLKEYLOGFILE=
set PYTHONIOENCODING=utf-8
chcp 65001 >nul

echo ========================================================
echo   Antigravity Autonomous Mobile Workstation (Telegram)
echo ========================================================
echo Starting Python Telegram Bot Daemon...
echo Authorized for: @noahlimjj
echo Relaying to Antigravity IDE...
echo Press Ctrl+C to stop.
echo.

:loop
"C:\Users\noahl\AppData\Local\Programs\Python\Python312\python.exe" bot.py
echo.
echo [!] Bot process stopped or crashed. Restarting in 5 seconds...
timeout /t 5 /nobreak >nul
goto loop
