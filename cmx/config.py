#!/usr/bin/env python3
#from cmx import config as cfg
#import pdb #pdb.set_trace()
from pathlib import Path


from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb import SMB_DIALECT
from impacket.smb3structs import SMB2_DIALECT_002, SMB2_DIALECT_21
from impacket.examples.secretsdump import RemoteOperations, SAMHashes
from impacket.examples.secretsdump import LSASecrets, NTDSHashes
from impacket.dcerpc.v5 import lsat, lsad
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from impacket.dcerpc.v5.dcom.wmi import WBEM_FLAG_FORWARD_ONLY
from impacket.dcerpc.v5.samr import SID_NAME_USE, USER_WORKSTATION_TRUST_ACCOUNT
from impacket.dcerpc.v5.samr import USER_SERVER_TRUST_ACCOUNT, MAXIMUM_ALLOWED
from impacket.dcerpc.v5.samr import USER_INFORMATION_CLASS
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5 import transport, scmr, srvs
from impacket.dcerpc.v5 import wkst, samr
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5.drsuapi import MSRPC_UUID_DRSUAPI
from impacket.dcerpc.v5.epm import hept_map
from impacket.dcerpc.v5 import epm

from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL




VERSION='1.0_azure'
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
PS_PATH = DATA_PATH / 'powershell_scripts'


PROC_PATH = CMX_HOME / 'procdump64.exe'
DUMP_PATH = 'safe.dmp'

AZ_PATH = CMX_HOME / 'azure'
AZ_CONFIG_PATH = AZ_PATH / 'configdone.txt'

TEST_PATH = CMX_HOME / 'test.txt'
