#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import pdb

import logging
import requests
import winrm as pywinrm

from io import StringIO

#import cmx
from cmx import config as cfg
from cmx.connection import *
from cmx.helpers.options import options
from cmx.helpers.logger import highlight, write_log
from cmx.helpers.misc import *
from cmx.helpers.wmirpc import RPCRequester
from cmx.logger import CMXLogAdapter

from impacket.smbconnection import SMBConnection, SessionError

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings()

class winrm(connection):

    def __init__(self, args, db, host):
        self.domain = None
        self.port = ' '
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
        self.debug = args.debug
        self.dc_ip = args.domaincontroller
        self.domain_dns = None

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        winrm_parser = parser.add_parser('winrm', help="own stuff using WINRM", parents=[std_parser, module_parser])
        winrm_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')

        winrm_parser.add_argument("-smbport", "--smbport", type=int, choices={445, 139}, default=445, help="SMB port (default: 445)")
        winrm_parser.add_argument("-dc", '--domaincontroller', type=str, default='', help='the IP of a domain controller')

        auth_group = winrm_parser.add_mutually_exclusive_group()
        auth_group.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, default=None, help="domain to authenticate to")
        auth_group.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')

        command_group = winrm_parser.add_argument_group("Command Execution", "Options for executing commands")
        command_group.add_argument('--no-output', action='store_true', help='do not retrieve command output')
        command_group.add_argument("-x", metavar="COMMAND", dest='execute', help="execute the specified command")
        command_group.add_argument("-X", metavar="PS_COMMAND", dest='ps_execute', help='execute the specified PowerShell command')

        return parser



    def proto_logger(self):
        self.logger = CMXLogAdapter(extra={
                                    'protocol': 'WinRM',
                                    'host': ('->' + self.host),
                                    'port': self.port,
                                    'hostname': self.hostname
                                    })
        #self.options.logger = self.logger


    def enum_host_info(self):
        """Fingerprint host via smb connection.

        Grabs info prior to unauthenticated
        """
        # self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]

        try:
            self.smbconn.login('', '')
            logging.debug("Null login?")
            self.logger.success('Null login allowed')
        except impacket.smbconnection.SessionError as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                logging.debug("Null login not allowed")
                pass

        self.domain     = self.smbconn.getServerDomain()           # OCEAN
        self.hostname   = self.smbconn.getServerName()             # WIN7-PC
        self.server_os  = self.smbconn.getServerOS()               # WIndows 6.1 Build 7601
        self.signing    = self.smbconn.isSigningRequired()         # True/false
        self.os_arch    = self.get_os_arch()                    # 64
        self.domain_dns = self.smbconn.getServerDNSDomainName()    # ocean.depth

        self.logger.hostname = self.hostname
        dialect = self.smbconn.getDialect()

        # print (self.conn.getServerDomain())            # OCEAN
        # print (self.conn.getServerName())              # WIN7-PC
        # print (self.conn.getServerOS())                # WIndows 6.1 Build 7601
        # print (self.conn.isSigningRequired())          # True
        # print (self.get_os_arch())                     # 64
        # print (self.conn.getDialect())                 # 528
        # print (self.conn.getRemoteHost())              # IPaddress
        # print (self.conn.getRemoteName())              # win7-pc
        # print (self.conn.getServerDNSDomainName())     # ocean.depth
        # print (self.conn.getServerOSMajor())           # 6
        # print (self.conn.getServerOSMinor())           # 1
        # print (self.conn.getServerOSBuild())           # 7601
        # print (self.conn.doesSupportNTLMv2())          # True
        # print (self.conn.isLoginRequired())            # True

        if dialect == impacket.smb.SMB_DIALECT:
            self.smbv = '1'
            logging.debug("SMBv1 dialect used")
        elif dialect == impacket.smb3structs.SMB2_DIALECT_002:
            self.smbv = '2.0'
            logging.debug("SMBv2.0 dialect used")
        elif dialect == impacket.smb3structs.SMB2_DIALECT_21:
            self.smbv = '2.1'
            logging.debug("SMBv2.1 dialect used")
        elif dialect == impacket.smb3structs.SMB2_DIALECT_30:
            self.smbv = '3.0'
            logging.debug("SMBv3.0 dialect used")
        elif dialect == impacket.smb3structs.SMB2_DIALECT_302:
            self.smbv = '3.0.2'
            logging.debug("SMBv3.0.2 dialect used")
        elif dialect == impacket.smb3structs.SMB2_DIALECT_311:
            self.smbv = '3.1.1'
            logging.debug("SMBv3.1.1 dialect used")
        else:
            self.smbv = '??'
            logging.debug("SMB version couldnt be determined?")

        # Get the DC if we arent local-auth and didnt specify
        if not self.args.local_auth and self.dc_ip == '':
            self.dc_ip = self.smbconn.getServerDNSDomainName()

        if self.args.domain:
            self.domain = self.args.domain

        if not self.domain:
            self.domain = self.hostname

        self.db.add_computer(self.host, self.hostname, self.domain, self.server_os)


        try:
            ''' DC's seem to want us to logoff first, windows workstations sometimes reset the connection
            '''
            self.smbconn.logoff()
        except:
            pass

        if self.args.local_auth:
            self.domain = self.hostname

        self.output_filename = '{}/{}_{}_{}'.format(cfg.LOGS_PATH,self.hostname, self.host, datetime.now().strftime("%Y-%m-%d_%H%M%S"))
        #Re-connect since we logged off
        self.create_conn_obj()



    def print_host_info(self):
        """Format help for host info."""
        self.logger.announce("{}{} (domain:{}) (signing:{}) (SMBv:{})".format(self.server_os,
                                                                              ' x{}'.format(self.os_arch) if self.os_arch else '',
                                                                              self.domain,
                                                                              self.signing,
                                                                              self.smbv))
        self.logger.announce('Targetting: {}'.format(self.endpoint))



    def create_smbv1_conn(self):
        """Setup connection using smbv1."""
        try:
            logging.debug('Attempting SMBv1 connection to {}'.format(self.host))
            self.smbconn = impacket.smbconnection.SMBConnection(self.host, self.host, None, self.args.smbport) #, preferredDialect=impacket.smb.SMB_DIALECT)
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
        """Setup connection using smbv3.

        Used for both SMBv2 and SMBv3
        """
        try:
            logging.debug('Attempting SMBv3 connection to {}'.format(self.host))
            self.smbconn = impacket.smbconnection.SMBConnection(self.host, self.host, None, self.args.smbport)
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

        #first figure out winrm endpoint -- could mabye just make them choose with/without SSL

        endpoints = [
            'https://{}:5986/wsman'.format(self.host),
            'http://{}:5985/wsman'.format(self.host)
        ]

        for url in endpoints:
            try:
                requests.get(url, verify=False, timeout=10)
                self.endpoint = url
                if self.endpoint.startswith('https://'):
                    self.port = 5986
                else:
                    self.port = 5985

                self.logger.extra['port'] = self.port

            except Exception as e:
                if 'Max retries exceeded with url' not in str(e):
                    logging.debug('Error in WinRM create_conn_obj:' + str(e))


        #then we build an smb connection to grab some hostinfo -
        #     - could maybe not do this and use output from winrm connection to get some info?
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

    def plaintext_login(self, domain, username, password):

        try:

            # pywinrm session class defined here :
            #      https://github.com/diyan/pywinrm/blob/master/winrm/__init__.py
            self.conn = pywinrm.Session(self.host,
                                        auth=('{}\\{}'.format(domain, username), password),
                                        transport='ntlm',
                                        server_cert_validation='ignore')
            # session = winrm.Session(host, auth=('{}@{}'.format(user,domain), password), transport='ntlm')

            # need to remove smb connection stuff and only use winrm
            self.smbconn.login(username, password, domain)
            self.password = password
            self.username = username
            self.domain = domain

            # using smb method until the warnings get fixed for urllib, just to cut down on warnings from execute
            self.admin_privs = self.check_if_admin()
            #r = self.conn.run_cmd('hostname')
            # self.parse_output(r)

            self.admin_privs = True
            self.logger.success('{}\\{}:{} {}'.format(domain,
                                                       username,
                                                       password,
                                                       highlight('({})'.format(cfg.pwn3d_label) if self.admin_privs else '')))

            return True

        except Exception as e:
            self.logger.error('{}\\{}:{} "{}"'.format(domain,
                                                       username,
                                                       password,
                                                       e))

            return False


###############################################################################

        ####### #     # #######  #####  #     # ####### #######
        #        #   #  #       #     # #     #    #    #
        #         # #   #       #       #     #    #    #
        #####      #    #####   #       #     #    #    #####
        #         # #   #       #       #     #    #    #
        #        #   #  #       #     # #     #    #    #
        ####### #     # #######  #####   #####     #    #######

###############################################################################

    def execute(self, payload=None, get_output=False):
        # run_cmd returns a Response() object
        # Response() object defined here: https://github.com/diyan/pywinrm/blob/master/winrm/__init__.py
        r = self.conn.run_cmd(self.args.execute)
        self.logger.success('Executed command')

        # result = session.run_cmd('ipconfig', ['/all']) # To run command in cmd
        # result = session.run_ps('Get-Acl') # To run Powershell block
        self.parse_output(r)

    def ps_execute(self, payload=None, get_output=False):
        r = self.conn.run_ps(self.args.ps_execute)
        self.logger.success('Executed command')
        self.parse_output(r)


####################################################################################

    #     #    #######    #          ######     #######    ######      #####
    #     #    #          #          #     #    #          #     #    #     #
    #     #    #          #          #     #    #          #     #    #
    #######    #####      #          ######     #####      ######      #####
    #     #    #          #          #          #          #   #            #
    #     #    #          #          #          #          #    #     #     #
    #     #    #######    #######    #          #######    #     #     #####

####################################################################################



    def parse_output(self, response_obj):
        if response_obj.status_code == 0:
            buf = StringIO(str(response_obj.std_out, 'UTF-8')).readlines()
            for line in buf:
                self.logger.highlight(line)
            return response_obj.std_out
        else:
            buf = StringIO(str(response_obj.std_err, 'UTF-8')).readlines()
            for line in buf:
                self.logger.highlight(line)
            return response_obj.std_err


    def check_if_admin(self):
        """Check for localadmin privs.

        Checked by view all services for sc_manager_all_access
        Returns:
            True if localadmin
            False if not localadmin
        """
        try:
            rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.host, 445, r'\svcctl', smb_connection=self.smbconn)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                logging.debug('localadmin Binding start')
                dce.bind(impacket.dcerpc.v5.scmr.MSRPC_UUID_SCMR)
                try:
                    # 0xF003F - SC_MANAGER_ALL_ACCESS
                    # this val comes from https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
                    # https://github.com/SecureAuthCorp/impacket/blob/master/impacket/dcerpc/v5/scmr.py

                    logging.debug('Verify localadmin via ServicesActive...')
                    ans = impacket.dcerpc.v5.scmr.hROpenSCManagerW(dce, '{}\x00'.format(self.hostname),'ServicesActive\x00', 0xF003F)
                    logging.debug('pewpewpewPwned baby')
                    dce.disconnect()
                    return True

                except impacket.dcerpc.v5.rpcrt.DCERPCException:
                    logging.debug('a {}'.format(str(e)))
                    dce.disconnect()
                    pass
            except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
                logging.debug('b {}'.format(str(e)))
                dce.disconnect()
                return False
        except Exception:
            logging.debug('Something went wrong ... Not localadmin :( ')
            dce.disconnect()
            return False

        dce.disconnect()
        return False


    def get_os_arch(self):
        """Identify OS architecture.

        Returns either 32 or 64
        """
        try:
            stringBinding = r'ncacn_ip_tcp:{}[135]'.format(self.host)
            rpctransport = impacket.dcerpc.v5.transport.DCERPCTransportFactory(stringBinding)
            rpctransport.set_connect_timeout(5)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            try:
                dce.bind(impacket.dcerpc.v5.epm.MSRPC_UUID_PORTMAP, transfer_syntax=('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
            except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
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
        except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
            pass

        return 64