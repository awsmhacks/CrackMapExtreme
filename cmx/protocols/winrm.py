import winrm as pywinrm #support for basic, certificate, and NTLM auth 
import requests
import logging
from io import StringIO
from impacket.smbconnection import SMBConnection, SessionError
from cmx.connection import *
from cmx.helpers.logger import highlight
from cmx.logger import CMXLogAdapter
from cmx import config as cfg



class winrm(connection):

    def __init__(self, args, db, host):
  
        self.hostname = None
        self.os_arch = None
        self.local_ip = None
        self.domain = None
        self.server_os = None
        self.os_arch = 0
        self.hash = None
        self.lmhash = ''
        self.nthash = ''
        self.remote_ops = None
        self.bootkey = None
        self.output_filename = None
        self.smbv1 = None
        self.signing = False
        self.debug = args.verbose
        self.dc_ip = ''

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        winrm_parser = parser.add_parser('winrm', help="own stuff using WINRM", parents=[std_parser, module_parser])
        winrm_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')
        winrm_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")
        dgroup = winrm_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, default=None, help="domain to authenticate to")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')
        cgroup = winrm_parser.add_argument_group("Command Execution", "Options for executing commands")
        cgroup.add_argument('--no-output', action='store_true', help='do not retrieve command output')
        cgroup.add_argument("-x", metavar="COMMAND", dest='execute', help="execute the specified command")
        cgroup.add_argument("-X", metavar="PS_COMMAND", dest='ps_execute', help='execute the specified PowerShell command')

        return parser

    def proto_flow(self):
        self.proto_logger()
        if self.create_conn_obj():
            self.enum_host_info()
            self.print_host_info()
            if self.login():
                if hasattr(self.args, 'module') and self.args.module:
                    self.call_modules()
                else:
                    self.call_cmd_args()

    def proto_logger(self):
        print('test')
        self.logger = CMXLogAdapter(extra={'protocol': 'WINRM',
                                        'host': self.host,
                                        'port': 'NONE',
                                        'hostname': 'NONE'})

    def enum_host_info(self):

        #smb_conn = SMBConnection(self.host, self.host, None)
#
        #try:
        #    smb_conn.login('' , '')
        #except SessionError as e:
        #    if "STATUS_ACCESS_DENIED" in str(e):
        #        pass
#
        #self.domain    = smb_conn.getServerDomain()
        #self.hostname  = smb_conn.getServerName()
        #self.server_os = smb_conn.getServerOS()
        #self.signing   = smb_conn.isSigningRequired()
        #self.os_arch   = smb_conn.get_os_arch()
#
        #self.output_filename = os.path.expanduser('~/.cme/logs/{}_{}_{}'.format(self.hostname, self.host, datetime.now().strftime("%Y-%m-%d_%H%M%S")))
#
        #if not self.domain:
        #    self.domain = self.hostname
#
        #self.db.add_computer(self.host, self.hostname, self.domain, self.server_os)
#
        #try:
        #    ''' DC's seem to want us to logoff first, windows workstations sometimes reset the connection
        #    '''
        #    smb_conn.logoff()
        #except:
        #    pass
#
        #if self.args.domain:
        #    self.domain = self.args.domain
#
        #if self.args.local_auth:
        #    self.domain = self.hostname
        print('todo')


    def print_host_info(self):
#>>> s.__dict__
#   {'url': 'http://win10a.ocean.depth:5985/wsman', 'protocol': <winrm.protocol.Protocol object at 0x7f7ae595f110>}
#>>> s.protocol.__dict__
#   {'read_timeout_sec': 30, 'operation_timeout_sec': 20, 'max_env_sz': 153600, 'locale': 'en-US', 'transport': <winrm.transport.Transport object at 0x7f7ae60a7f50>, 'username': 'agrande', 'password': 'User!23', 'service': 'HTTP', 'keytab': None, 'ca_trust_path': None, 'server_cert_validation': 'validate', 'kerberos_delegation': False, 'kerberos_hostname_override': None, 'credssp_disable_tlsv1_2': False}
#   
        self.logger.info("{}".format(self.conn.url))


    def create_conn_obj(self):
        #pywinrm will try and guess the correct endpoint url: https://pypi.org/project/pywinrm/0.2.2/
        print('pass={}'.format(self.args.password))
        self.conn = pywinrm.Session(self.host,
                                    auth=('{}\\{}'.format(self.domain, self.args.username[0]), self.args.password[0]),
                                    transport='ntlm',
                                    server_cert_validation='ignore')
        return True


    def plaintext_login(self, domain, username, password):
        try:
            self.conn.run_cmd('hostname')
            self.admin_privs = True
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

    def parse_output(self, response_obj):
        if response_obj.status_code == 0:
            buf = StringIO(response_obj.std_out).readlines()
            for line in buf:
                self.logger.highlight(line.decode('utf-8').strip())

            return response_obj.std_out

        else:
            buf = StringIO(response_obj.std_err).readlines()
            for line in buf:
                self.logger.highlight(line.decode('utf-8').strip())

            return response_obj.std_err

    def execute(self, payload=None, get_output=False):
        r = self.conn.run_cmd(self.args.execute)
        self.logger.success('Executed command')
        self.parse_output(r)

    def ps_execute(self, payload=None, get_output=False):
        r = self.conn.run_ps(self.args.ps_execute)
        self.logger.success('Executed command')
        self.parse_output(r)