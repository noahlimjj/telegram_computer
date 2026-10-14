Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\Users\noahl\.gemini\antigravity\scratch\telegram-agent-bot"
WshShell.Run "cmd /c set SSLKEYLOGFILE= && set PYTHONIOENCODING=utf-8 && chcp 65001 >nul && ""C:\Users\noahl\AppData\Local\Programs\Python\Python312\python.exe"" bot.py", 0, False
