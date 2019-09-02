
```                                          
    ____ ____ ____ ____ _  _     _  _ ____ ___      ____ _  _ ___ ____ ____ _  _ ____ 
    |    |__/ |__| |    |_/      |\/| |__| |__]     |___  \/   |  |__/ |___ |\/| |___ 
    |___ |  \ |  | |___ | \_     |  | |  | |        |___ _/\_  |  |  \ |___ |  | |___ 
		                                  			    
		   Crack Map Exec - eXtreme edition                
```

[General Overview](https://github.com/awsmhacks/CrackMapExtreme/blob/master/docs/CMX-Usage-Home.md)  
[SMB: Command Execution Reference](https://github.com/awsmhacks/CrackMapExtreme/blob/master/docs/SMB-Command-Reference.md)
[Mimikatz](https://github.com/awsmhacks/CrackMapExtreme/blob/master/docs/SMB-Module-Reference.md#mimikatz)  

------------------------------------------------------------------------

This is a python3 rewrite of CrackMapExec.  
As I was converting, several issues came up due to dependancies that I ended up changing a bit of how things work.
  
Not all modules have been carried over yet and this is still a work in progress.  
Feel free to open issues, I know of a few (usually due to target OS compatibility)  
but will still use the issue log to track/address.  

Same cme feels, just a bit different under-the-hood.  
  
------------------------------------------------------------------------
# CrackMapExtreme

Firstly, of course, major props to the one and only [@byt3bl33d3r](https://github.com/byt3bl33d3r) for creating the original CME.  
Have a look at his latest project over at [SilentTrinity](https://github.com/byt3bl33d3r/SILENTTRINITY)  

Second, wowz omg to the guys over at [SecureAuthCorp](https://github.com/byt3bl33d3r) for impacket. Notably [asolino](https://github.com/asolino) and [dirkjanm](https://github.com/dirkjanm)  
CMX merely feels like a wrapper script around all their awesomeness (this version at least ;)  

You'll find new features and use-case's, check the command exec guide for some of them.   
Still lots to do but I'm getting there.  
I'll start an upcoming/planned features log here at some point.  

Also note, there's a ton of half-documented functions / over-used debug statements / and commented out code currently.  
After things smooth out I'll get to fully documenting and cleanup.   


SMB modules are just getting going but there are a few in progress.    
Mimikatz, for the most part, is working (i think)   
  
WinRM is the only other protocol at this point but certainly not ready.   


##### Kali Quickstart

```  
apt install pipenv
cd /opt
git clone https://github.com/awsmhacks/CrackMapExtreme 
cd /opt/CrackMapExtreme  
pipenv install --three               #ignore the errors and continue
pipenv shell  
pip install -r requirements.txt 
python setup.py -q install 
cmx
```
