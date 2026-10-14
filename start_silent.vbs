' Launched at login from the Startup folder. Opens Antigravity IDE (the bot forwards
' prompts into it) and runs the bot hidden via start_bot.bat, which restarts it on crash.
Set WshShell = CreateObject("WScript.Shell")
Set Fso = CreateObject("Scripting.FileSystemObject")
WshShell.CurrentDirectory = "C:\Users\noahl\.gemini\antigravity\scratch\telegram-agent-bot"

ideExe = "C:\Users\noahl\AppData\Local\Programs\Antigravity IDE\Antigravity IDE.exe"
Set running = GetObject("winmgmts:").ExecQuery("SELECT * FROM Win32_Process WHERE Name='Antigravity IDE.exe'")
If running.Count = 0 And Fso.FileExists(ideExe) Then
    WshShell.Run """" & ideExe & """", 1, False
End If

' Don't start a second bot if one is already running
Set bots = GetObject("winmgmts:").ExecQuery("SELECT * FROM Win32_Process WHERE Name='python.exe' AND CommandLine LIKE '%bot.py%'")
If bots.Count = 0 Then
    WshShell.Run "cmd /c """ & WshShell.CurrentDirectory & "\start_bot.bat""", 0, False
End If
