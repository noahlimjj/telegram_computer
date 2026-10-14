' Launched at login from the Startup folder. Opens Antigravity IDE (the bot forwards
' prompts into it) and runs the bot hidden via start_bot.bat, which restarts it on crash.
' Each step is logged to launcher.log so a failed autostart can be diagnosed.
Set WshShell = CreateObject("WScript.Shell")
Set Fso = CreateObject("Scripting.FileSystemObject")
botDir = "C:\Users\noahl\.gemini\antigravity\scratch\telegram-agent-bot"
WshShell.CurrentDirectory = botDir

Sub LogLine(msg)
    On Error Resume Next
    Set f = Fso.OpenTextFile(botDir & "\launcher.log", 8, True)
    f.WriteLine Now & "  " & msg
    f.Close
End Sub

Function ProcessCount(wql)
    ' -1 when the WMI query itself fails (e.g. too early during login)
    On Error Resume Next
    ProcessCount = -1
    Set results = GetObject("winmgmts:").ExecQuery(wql)
    If Err.Number = 0 Then ProcessCount = results.Count
    If Err.Number <> 0 Then ProcessCount = -1
End Function

LogLine "launcher started"

ideExe = "C:\Users\noahl\AppData\Local\Programs\Antigravity IDE\Antigravity IDE.exe"
ideCount = ProcessCount("SELECT * FROM Win32_Process WHERE Name='Antigravity IDE.exe'")
If ideCount = 0 And Fso.FileExists(ideExe) Then
    WshShell.Run """" & ideExe & """", 1, False
    LogLine "opened Antigravity IDE"
Else
    LogLine "IDE already running or check failed (count=" & ideCount & ")"
End If

' Don't start a second bot if one is already running; if the check fails, start anyway
botCount = ProcessCount("SELECT * FROM Win32_Process WHERE Name='python.exe' AND CommandLine LIKE '%bot.py%'")
If botCount <= 0 Then
    WshShell.Run "cmd /c """ & botDir & "\start_bot.bat""", 0, False
    LogLine "started bot (check count=" & botCount & ")"
Else
    LogLine "bot already running, not starting another"
End If
