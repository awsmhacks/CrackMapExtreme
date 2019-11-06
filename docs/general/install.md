---
layout: default
title: Installation
---

[Just gimmie the install commands](#quick-start)

## Default Kali Install 

I recommend using a pipenv for all installations, getting pipenv on Kali is simple.    

`#~ apt install pipenv`  

Installing into the /opt directory on Kali would then follow:  
```
#~ cd /opt
#~ git clone https://github.com/awsmhacks/CrackMapExtreme 

#~ cd /opt/CrackMapExtreme  
#~ pipenv --three  
#~ pipenv shell  
#~ pip install -r requirements.txt  
```

Before building the package you may want to have a look at the /cmx/config.py file.  
Read more about configure cmx [Here](./configuration)  
  
CMX defaults to using ~/.cmx/ for output directories.    
After making modifications or if you just want to use defaults, finish the installtion.  

```
#~ python setup.py -q install           (remove the -q if you want to look cool)
```
Then test out the installation
```
#~ cmx
```
The first time `cmx` is launched on a machine it checks for the installation 
directories defined in config.py.   
If it doesnt see them we assume a first-time install 
and cmx will build out the files and locations it needs.  
  
```
[*] Creating default workspace
[*] Initializing SMB protocol database
[*] Initializing WINRM protocol database
[*] Generating SSL certificate
Generating a RSA private key
..........................................+++++
.+++++
writing new private key to '/root/.cmx/cmxkey.pem'
-----
____ ____ ____ ____ _  _   _  _ ____ ___    ____ _  _ ___ ____ ____ _  _ ____ 
|    |__/ |__| |    |_/    |\/| |__| |__]   |___  \/   |  |__/ |___ |\/| |___ 
|___ |  \ |  | |___ | \_   |  | |  | |      |___ _/\_  |  |  \ |___ |  | |___ 

         A swiss army knife for pentesting networks
    Forged by @byt3bl33d3r using the powah of dank memes
            R3born from the ashes by @awsmhacks
                    Version: 5.0.1
        (/.__.)/ The python3 EXTREME edition \(.__.\) 

Usage: 
       cmx [--verbose] PROTOCOL [-h] TARGET [target options] [-M MODULE [module options]]  

       cmx smb -L                       (List of <smb> modules)
       cmx smb -M mimikatz --options    (List a particular module's options)
       cmx smb 10.10.10.10 -u Administrator -p Password --recon
       cmx -D smb 192.168.1.1 -u username -p password -M mimikatz

 *Check the /docs/ for detailed usage* 
```

If you need to change the output directory or other configurations   
just rebuild after making your changes.  
  

Type `exit` to return from the pip environment.  
To jump back into the pip environment, navigate to the cmx root folder (/opt/CrackMapExtreme)  
and type `pipenv shell`  
  
--------------------------------------------------------------------------------------- 

# 
  
# Quick Start
  
These commands should work on a default kali 2019.3 install.  

```
apt install pipenv
cd /opt
git clone https://github.com/awsmhacks/CrackMapExtreme 
cd CrackMapExtreme  
pipenv --three
pipenv shell  
pip install -r requirements.txt 
python setup.py -q install 
cmx
```  
   
Default logs and file locations = ~/.cmx/  
Make edits to /cmx/config.py and re-run `setup.py install` if needed   