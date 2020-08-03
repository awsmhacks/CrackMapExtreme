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

Second, wowz omg to the guys over at [SecureAuthCorp](https://github.com/byt3bl33d3r) for impacket. Notably [asolino](https://github.com/asolino) and [dirkjanm](https://github.com/dirkjanm)  

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
Same cme feels, just a bit different under-the-hood.  
