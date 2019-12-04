

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
        commandgroup.add_argument('--users', action='store_true', help='Enumerate and return all users')
        commandgroup.add_argument('--group', nargs='?', const='', metavar='GROUP', help='Enumerate and return all members of a group')
        commandgroup.add_argument('--groups', action='store_true', help='Enumerate and return all groups')
        commandgroup.add_argument('--usergroups', nargs='?', const='', metavar='USERSGROUPS', help='Enumerate and return all groups a user is a member of')

        commandgroup.add_argument('--suggest', action='store_true', help='Check for potentially abusable permissions')
        commandgroup.add_argument('--privs', action='store_true', help='Check current users privileges')

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
#   
#   
#   
#   
# (fold next line)
###############################################################################


    def user(self):
        user_id = subprocess.run(['az','ad', 'user', 'show', '--id', self.args.user], stdout=subprocess.PIPE)
        user_id_json = json.loads(user_id.stdout.decode('utf-8'))
        pprint.pprint(user_id_json)


    def usergroups(self):
        users_groups = subprocess.run(['az','ad', 'user', 'get-member-groups', '--id', self.args.usergroups], stdout=subprocess.PIPE)
        users_groups_json = json.loads(users_groups.stdout.decode('utf-8'))
        pprint.pprint(users_groups_json)


    def users(self):
        user_id = subprocess.run(['az','ad', 'user', 'list', '--query', '[].{display_name:displayName, description: description, object_id: objectId}'], stdout=subprocess.PIPE)
        user_id_json = json.loads(user_id.stdout.decode('utf-8'))
        pprint.pprint(user_id_json)


    def group(self):
        group_list = subprocess.runsubprocess.run(['az','ad', 'group', 'list', '--id', self.args.group, '--query', '[].{display_name:displayName, description: description, object_id: objectId}'], stdout=subprocess.PIPE)
        group_list_json = json.loads(group_list.stdout.decode('utf-8'))
        pprint.pprint(group_list_json)

    def groups(self):
        group_list = subprocess.runsubprocess.run(['az','ad', 'group', 'list', '--query', '[].{display_name:displayName, description: description, object_id: objectId}'], stdout=subprocess.PIPE)
        group_list_json = json.loads(group_list.stdout.decode('utf-8'))
        pprint.pprint(group_list_json)



    def suggest(self):

        # Grab user UPN
        upn_resp = subprocess.run(['az', 'ad', 'signed-in-user', 'show','--query', '{upn:userPrincipalName}'], stdout=subprocess.PIPE)
        upn_json_obj = json.loads(upn_resp.stdout.decode('utf-8'))
        upn = upn_json_obj['upn']
        pprint.pprint(upn)

        # GetCurrent users roles
        role_resp = subprocess.run(['az', 'role', 'assignment', 'list', '--assignee', upn, '--query', '[].{roleName:roleDefinitionName}'], stdout=subprocess.PIPE)
        try:
            role_json_obj = json.loads(role_resp.stdout.decode('utf-8'))
        except:
            self.logger.error("Current users has no subscriptions")
            return

        role_list = []
        for role in role_json_obj:
            role_list.append(role["roleName"])

        if(len(role_list) == 0):
            self.logger.error("No roles found")
        return

        # Get definitions for each role
        tmp_list_perms = []
        for role in role_list:
            #print(role.upper())
            role_show = subprocess.run(['az', 'role', 'definition', 'list', '--name', role, '--query', '[].{actions:permissions[].actions, dataActions:permissions[].dataActions, notActions:permissions[].notActions, notDataActions:permissions[].NotDataActions}'], stdout=subprocess.PIPE)
            role_show_json = json.loads(role_show.stdout.decode('utf-8'))
            tmp_list_perms.append(role_show_json[0]['actions'][0])

        all_permissions = [item for sublist in tmp_list_perms for item in sublist]

        self.check_perms(all_permissions)


    def check_perms(self, permissions):

        self.logger.announce("Getting potentially abusable global permissions")
        for perm in permissions:
            if("*" in perm):
                self.logger.highlight("Found permission with * - should investigate: {}".format(perm))
            elif("write" in perm):
                self.logger.highlight(" found permission with write - should investigate: {}".format(perm))
            elif("create" in perm):
                self.logger.highlight(" found permission with create - should investigate: {}".format(perm))
            elif("delete" in perm):
                self.logger.highlight(" found permission with delete - should investigate: {}".format(perm))


        self.logger.announce("Checking specific permissions")
        for perm in permissions:

            if("Microsoft.Authorization/*" in perm):
                self.logger.highlight("Current user has permission to do all authorizations actions to resources - consider RBAC manipulation and adding a backdoor AD user")
            if("Microsoft.Authorization/*/read" in perm):
                self.logger.highlight("Current user has permission to read all authorizations - consider running the priv domain enum module")


            if("Microsoft.Compute/*" in perm):
                self.logger.highlight("Current user has permission to run all operations for all resource types - consider using the exfil modules")
            if("Microsoft.Compute/*/read" in perm):
                self.logger.highlight("Current user has permission to read all compute related resources - consider using the various 'list' modules")


            if("Microsoft.Support/*" in perm):
                self.logger.highlight("Current user has permission to issue and submit support tickets")


            if("Microsoft.Resources/*" in perm):
                self.logger.highlight("Current user has permission to run all Microsoft.Resources related commands")
            elif("Microsoft.Resources/deployments/*" in perm):
                self.logger.highlight("Current user has permission to run all deployment related commands")
            elif("Microsoft.Resources/deployments/subscriptions/*" in perm):
                self.logger.highlight("Current user has permission to run all subscription related commands")


            if("Microsoft.Network/*" in perm):
                self.logger.highlight("Current user has permission to run all networking related commands - consider running the net modules")
            elif("Microsoft.Network/networkSecurityGroups/*" in perm):
                self.logger.highlight("Current user has permission to run all nsg related commands - consider running the nsg backdoor module")
            elif("Microsoft.Network/networkSecurityGroups/join/action" in perm):
                self.logger.highlight("Current user has permission to join a network security group ")
                

            if("Microsoft.Compute/virtualMachines/*" in perm):
                self.logger.highlight("Current user has permission to run virtual machine commands - consider running the various vm modules ")
            elif("Microsoft.Compute/virtualMachines/runCommand/action" in perm or "Microsoft.Compute/virtualMachines/runCommand/*" in perm):
                self.logger.highlight("Current user has permission to run the runCommand virtual machine command - consider running the vm_rce ")


            if("Microsoft.Compute/virtualMachinesScaleSets/*" in perm):
                self.logger.highlight("Current user has permission to run virtual machine scale set commands - consider running the various vmss modules ")
            elif("Microsoft.Compute/virtualMachinesScaleSets/runCommand/action" in perm or "Microsoft.Compute/virtualMachines/runCommand/*" in perm):
                self.logger.highlight("Current user has permission to run the runCommand virtual machine scale set command - consider running the vmss_rce ")


            if("Microsoft.Storage/*" in perm or "Microsoft.Storage/storageAccounts/*" in perm):
                self.logger.highlight("Current user has permission to run all storage account commands - consider running the various stg modules ")
            elif("Microsoft.Storage/storageAccounts/blobServices/containers/*" in perm):
                self.logger.highlight("Current user has permissions to run all storage account container commands - consider running the various stg modules ")
            elif("Microsoft.Storage/storageAccounts/listKeys/action" in perm):
                self.logger.highlight("Current user has permission to read storage account keys - consider running the stg blob scan/download modules ")


            if("Microsoft.Sql/*" in perm):
                self.logger.highlight("+]Current user has permission to run all sql commands - consider running the various sql modules ")
            elif("Microsoft.Sql/servers/*" in perm):
                self.logger.highlight("+]Current user has permission to run all sql server commands - consider running the sql server list or the sql backdoor firewall modules ")
            elif("Microsoft.Sql/servers/databases/*" in perm):
                self.logger.highlight("+]Current user has permission to run all sql database commands - consider running the sql db list ")
            

    def privs(self):
        # Grab user UPN
        upn_resp = subprocess.run(['az', 'ad', 'signed-in-user', 'show','--query', '{upn:userPrincipalName}'], stdout=subprocess.PIPE)
        upn_json_obj = json.loads(upn_resp.stdout.decode('utf-8'))
        upn = upn_json_obj['upn']

        # GetCurrent users roles
        role_resp = subprocess.run(['az', 'role', 'assignment', 'list', '--assignee', upn, '--query', '[].{roleName:roleDefinitionName}'], stdout=subprocess.PIPE)
        try:
            role_json_obj = json.loads(role_resp.stdout.decode('utf-8'))
        except:
            self.logger.error("Current users has no subscriptions")
            return

        role_list = []
        for role in role_json_obj:
            role_list.append(role["roleName"])

        if(len(role_list) == 0):
            self.logger.error("No roles found")
        return

        for role in role_list:
            #print(role.upper())
            role_show = subprocess.run(['az', 'role', 'definition', 'list', '--name', role, '--query', '[].{actions:permissions[].actions, dataActions:permissions[].dataActions, notActions:permissions[].notActions, notDataActions:permissions[].NotDataActions}'], stdout=subprocess.PIPE)
            role_show_json = json.loads(role_show.stdout.decode('utf-8'))
            pprint.pprint(role_show_json)