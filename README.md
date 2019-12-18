```                                          
    ____ ____ ____ ____ _  _     _  _ ____ ___      ____ _  _ ___ ____ ____ _  _ ____ 
    |    |__/ |__| |    |_/      |\/| |__| |__]     |___  \/   |  |__/ |___ |\/| |___ 
    |___ |  \ |  | |___ | \_     |  | |  | |        |___ _/\_  |  |  \ |___ |  | |___ 
		                                  			    
                            CrackMapExec - eXtreme edition                
```

**Check the new (and in progress) cmx documentation site!** [C M X](https://awsmhacks.github.io/cmxdocs/index)    
  
  
------------------------------------------------------------------------
# CrackMapExtreme

Firstly, of course, major props to the one and only [@byt3bl33d3r](https://github.com/byt3bl33d3r) for creating the original CME.  
Have a look at his latest project over at [SilentTrinity](https://github.com/byt3bl33d3r/SILENTTRINITY)  

Second, wowz omg to the guys over at [SecureAuthCorp](https://github.com/byt3bl33d3r) for impacket. Notably [asolino](https://github.com/asolino) and [dirkjanm](https://github.com/dirkjanm)  
CMX merely feels like a wrapper script around all their awesomeness (this version at least ;)  


##### Kali Quickstart

```  
apt install pipenv
cd /opt
git clone https://github.com/awsmhacks/CrackMapExtreme 
cd /opt/CrackMapExtreme  
pipenv --three               #ignore any errors and continue
pipenv shell  
pip install -r requirements.txt 
python setup.py -q install 
cmx
```

------------------------------------------------------------------------


This started off as a python3 update to CrackMapExec.  
As I was converting, several issues came up due to dependancies that I ended up changing a bit of how things work.  
  
Not all modules have been carried over yet and this is still a work in progress.  
Feel free to open issues, I know of a few (usually due to target OS compatibility)  
but will still use the issue log to track/address.  
  
Same cme feels, just a bit different under-the-hood.  
