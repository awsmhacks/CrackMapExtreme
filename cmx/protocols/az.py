

import cmx

from cmx import config as cfg
from cmx.helpers.logger import highlight, write_log
from cmx.logger import CMXLogAdapter

from azure.cli.core import get_default_cli
from azure.cli.core._session import ACCOUNT, CONFIG, SESSION
from azure.cli.core._environment import get_config_dir
from azure.cli.core.util import CLIError

import os
import subprocess
import json
import pprint

class az(connection):

    def __init__(self, args, db, host):
  
        self.hostname = 'azureAD'
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
        self.args = args
        self.dc_ip = ''
        self.az_cli = None

        if args.config:
            self.config1()
        else:
            self.proto_flow()


    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        azure_parser = parser.add_parser('az', help="owning over azure", parents=[std_parser, module_parser])
        configgroup = azure_parser.add_argument_group("Configure Azure CLI", "Configure the Azure Connection")
        configgroup.add_argument('--config', action='store_true', help='Setup or re-bind azure connection')

        commandgroup = azure_parser.add_argument_group("Command Execution", "Options for executing commands")
        commandgroup.add_argument("-x", metavar="COMMAND", dest='execute', help="execute the specified command")
        commandgroup.add_argument('--user', nargs='?', const='', metavar='USER', help='Enumerate and return all info about a domain user')
        commandgroup.add_argument('--usersgroups', nargs='?', const='', metavar='USER', help='Enumerate and return all groups a users is a member of')

        return parser
       

    def proto_flow(self):
        self.proto_logger()
        if self.test_connection():
            self.call_cmd_args()


    def proto_logger(self):
        self.logger = CMXLogAdapter(extra={'protocol': 'AZURE',
                                        'host': 'CLI',
                                        'port': ' ',
                                        'hostname': self.hostname})

    def test_connection(self):
        if not cfg.AZ_CONFIG_PATH.is_file():
            self.logger.error('Azure connection has not been configured.')
            self.logger.error('Run: cmx az 1 --config')
            return False

        self.az_cli = get_default_cli()

        return True



    def user(self):
        user_id = subprocess.run(['az','ad', 'user', 'show', '--id', self.args.users], stdout=subprocess.PIPE)
        user_id_json = json.loads(user_id.stdout.decode('utf-8'))
        pprint.pprint(user_id_json)


    def usersgroups(self):
        users_groups = subprocess.run(['az','ad', 'user', 'get-member-groups', '--id', self.args.usersgroups], stdout=subprocess.PIPE)
        users_groups_json = json.loads(users_groups.stdout.decode('utf-8'))
        pprint.pprint(user_id_json)


    def config1(self):
        login = subprocess.run(['az','login', '--allow-no-subscriptions'], stdout=subprocess.PIPE)
        user = re.findall('([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', str(login.stdout))
        #self.logger.success('Logged in as {}'.format(user[0]))
        print("               Logged in as {}".format(user[0]))

        if not cfg.AZ_PATH.is_dir():
            cfg.AZ_PATH.mkdir(parents=True, exist_ok=True)

        if not cfg.AZ_CONFIG_PATH.is_file():
            f = open(cfg.AZ_CONFIG_PATH,"w+")
            f.write("azure config completed")
            f.close()
        print("               Azure Services now configured, Go get em tiger")


    def call_cmd_args(self):
        for k, v in list(vars(self.args).items()):
            if hasattr(self, k) and hasattr(getattr(self, k), '__call__'):
                if v is not False and v is not None:
                    logging.debug('Calling {}()'.format(k))
                    getattr(self, k)()


    def execute(self, command):
        try:
            result = self.az_cli.invoke(command)
            return {
                'result': result.result,
                'error': None
            }
        except CLIError as err:
            return {
                'result': None,
                'error': err.args
            }
