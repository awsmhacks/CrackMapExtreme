#!/usr/bin/env python3
#from cmx import config as cfg
#import pdb #pdb.set_trace()
from pathlib import Path


VERSION='5.0.1'
RELEASED='n/a'

# grabs the install directory to reference cmx's location.
# dont edit this one. 
CMX_DIR = Path(__file__).parents[0]

########################################################################
#                    Make Edits below this line                        #
########################################################################

WORKSPACE = 'default'
last_used_db = None
pwn3d_label = 'Pwn3d!'

#Modify the home directory where everything gets stored
CMX_HOME = Path.home() / '.cmx'

TMP_PATH = CMX_HOME / 'tmp'
WS_PATH = CMX_HOME / 'workspaces'
CERT_PATH = CMX_HOME / 'cmxcert.pem'
KEY_PATH = CMX_HOME / 'cmxkey.pem'
CONFIG_PATH = CMX_HOME / 'cmx.conf'
LOGS_PATH = CMX_HOME / 'logs'
OBF_PATH = CMX_HOME / 'obfuscated_scripts'


THIRD_PARTY_PATH = CMX_DIR / 'thirdparty'
CMX_MOD_DIR = CMX_DIR / 'modules'
CMX_PROTO_DIR = CMX_DIR / 'protocols'
DATA_PATH = CMX_DIR / 'data'