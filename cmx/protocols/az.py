

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

import pdb

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
        self.username = ''
        self.domain = ''

        if args.config:
            self.config1()
        else:
            self.proto_flow()


    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        azure_parser = parser.add_parser('az', help="owning over azure", parents=[std_parser, module_parser])
        configgroup = azure_parser.add_argument_group("Configure Azure CLI", "Configure the Azure Connection")
        configgroup.add_argument('--config', action='store_true', help='Setup or re-bind azure connection')

        #commandgroup = azure_parser.add_argument_group("Command Execution", "Options for executing commands")
        #commandgroup.add_argument("-x", metavar="COMMAND", dest='execute', help="execute the specified command")

        enumgroup = azure_parser.add_argument_group("Enumeration", "Azure AD Enumeration Commands")
        enumgroup.add_argument('--user', nargs='?', const='', metavar='USER', help='Enumerate and return all info about a user')
        enumgroup.add_argument('--users', action='store_true', help='Enumerate and return all users')
        enumgroup.add_argument('--group', nargs='?', const='', metavar='GROUP', help='Enumerate and return all members of a group')
        enumgroup.add_argument('--groups', action='store_true', help='Enumerate and return all groups')
        enumgroup.add_argument('--usergroups', nargs='?', const='', metavar='USERSGROUPS', help='Enumerate and return all groups a user is a member of')

        privgroup = azure_parser.add_argument_group("Privilege Checks", "Get Privs and identify PrivEsc")
        privgroup.add_argument('--suggest', action='store_true', help='Check for potentially abusable permissions')
        privgroup.add_argument('--privs', nargs='?', const='', metavar='USER', help='Check current users privileges')

        resourcegroup = azure_parser.add_argument_group("Resource Checks", "Interact with resources")
        resourcegroup.add_argument('--rgroups', action='store_true', help='List all Resource Groups for current subscription')

        sqlgroup = azure_parser.add_argument_group("SQL Commands", "Interact with SQL Servers and DBs")
        sqlgroup.add_argument('--sql-list', action='store_true', help='List all SQL Servers for current subscription')
        sqlgroup.add_argument('--sql-db-list', nargs='?', const='', metavar='USER', help='List all SQL DBs for current subscription')

        storagegroup = azure_parser.add_argument_group("Storage Commands", "Interact with Storage")
        storagegroup.add_argument('--storage-list', action='store_true', help='List all Storage for current subscription')

        vmgroup = azure_parser.add_argument_group("VM Checks", "Interact with VMs and VM Scale Sets")
        vmgroup.add_argument('--vm-list', nargs='?', const='', metavar='RESOURCEGROUP', help='List all VMs for current subscription or target resource group')
        vmgroup.add_argument('--vmss-list', nargs='?', const='', metavar='RESOURCEGROUP', help='List all VM Scale Sets for current subscription or target resource group')

        spngroup = azure_parser.add_argument_group("SPN Checks", "Interact with Service Principals")
        spngroup.add_argument('--spn-list', action='store_true', help='List all SPNs for current subscription')

        return parser
       

    def proto_flow(self):
        self.proto_logger()
        if self.test_connection():
            self.call_cmd_args()

    def proto_logger(self):
        self.logger = CMXLogAdapter(extra={'protocol': 'AZURE',
                                        'host': self.username,
                                        'port': self.domain,
                                        'hostname': 'CLI'})

    def test_connection(self):
        if not cfg.AZ_CONFIG_PATH.is_file():
            self.logger.error('Azure connection has not been configured.')
            self.logger.error('Run: cmx az 1 --config')
            return False

        # Grab our user/domain and re-init logger. 
        # Config should have stored this in the config file.
        f = open(cfg.AZ_CONFIG_PATH,"r")
        data = f.read()
        f.close()
        self.username = data.split()[0].split('@')[0]
        self.domain = data.split()[0].split('@')[1]
        self.proto_logger()


        self.az_cli = get_default_cli()

        return True


    def config1(self):
        self.proto_logger()

        login = subprocess.run(['az','login', '--allow-no-subscriptions'], stdout=subprocess.PIPE)
        user = re.findall('([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', str(login.stdout))
        #print("               Logged in as {}".format(user[0]))
        self.logger.success('Logged in as {}'.format(user[0]))

        if not cfg.AZ_PATH.is_dir():
            cfg.AZ_PATH.mkdir(parents=True, exist_ok=True)

    
        f = open(cfg.AZ_CONFIG_PATH,"w")
        f.write("{}".format(user[0]))
        f.close()
        print('')
        print("               Azure Services now configured, Go get em tiger")
        print('')


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

           #       ######              ####### #     # #     # #     # 
          # #      #     #             #       ##    # #     # ##   ## 
         #   #     #     #             #       # #   # #     # # # # # 
        #     #    #     #    #####    #####   #  #  # #     # #  #  # 
        #######    #     #             #       #   # # #     # #     # 
        #     #    #     #             #       #    ## #     # #     # 
        #     #    ######              ####### #     #  #####  #     # 
                                                                
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

        user_id = subprocess.run(['az','ad', 'user', 'show', '--id', self.args.user], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            user_id_json = json.loads(user_id.stdout.decode('utf-8'))
        except:
            self.logger.error("Current user has no subscriptions")
            return
        
        #pdb.set_trace()
        pprint.pprint(user_id_json)


    def usergroups(self):
        users_groups = subprocess.run(['az','ad', 'user', 'get-member-groups', '--id', self.args.usergroups], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            users_groups_json = json.loads(users_groups.stdout.decode('utf-8'))
        except:
            self.logger.error("Current user has no subscriptions")
            return
        pprint.pprint(users_groups_json)


    def users(self):
        user_id = subprocess.run(['az','ad', 'user', 'list', '--query', '[].{display_name:displayName, description: description, object_id: objectId}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            user_id_json = json.loads(user_id.stdout.decode('utf-8'))
        except:
            self.logger.error("Current user has no subscriptions")
            return
        pprint.pprint(user_id_json)


    def group(self):
        if self.args.group == '':
            self.logger.error('Must provide a group name or objectID')
            return
        
        group_list = subprocess.runsubprocess.run(['az','ad', 'group', 'member', 'list', '--group', self.args.group ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            group_list_json = json.loads(group_list.stdout.decode('utf-8'))
        except:
            self.logger.error("Current user has no subscriptions")
            return
        pprint.pprint(group_list_json)


    def groups(self):
        group_list = subprocess.runsubprocess.run(['az','ad', 'group', 'list', '--query', '[].{display_name:displayName, description: description, object_id: objectId}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            group_list_json = json.loads(group_list.stdout.decode('utf-8'))
        except:
            self.logger.error("Current user has no subscriptions")
            return
        pprint.pprint(group_list_json)


###############################################################################

        ######  ######     ###    #     #       #######  #####   #####  
        #     # #     #     #     #     #       #       #     # #     # 
        #     # #     #     #     #     #       #       #       #       
        ######  ######      #     #     #       #####    #####  #       
        #       #   #       #      #   #        #             # #       
        #       #    #      #       # #         #       #     # #     # 
        #       #     #    ###       #          #######  #####   #####  

###############################################################################
###############################################################################
#
#
#
#
###############################################################################

    def suggest(self):

        # Grab user UPN
        upn_resp = subprocess.run(['az', 'ad', 'signed-in-user', 'show','--query', '{upn:userPrincipalName}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        upn_json_obj = json.loads(upn_resp.stdout.decode('utf-8'))
        upn = upn_json_obj['upn']
        logging.debug('upn: {}'.format(upn))

        # GetCurrent users roles
        role_resp = subprocess.run(['az', 'role', 'assignment', 'list', '--assignee', upn, '--query', '[].{roleName:roleDefinitionName}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            role_json_obj = json.loads(role_resp.stdout.decode('utf-8'))
        except:
            self.logger.error("Current user has no subscriptions")
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
                self.logger.highlight("Current user has permission to run all sql commands - consider running the various sql modules ")
            elif("Microsoft.Sql/servers/*" in perm):
                self.logger.highlight("Current user has permission to run all sql server commands - consider running the sql server list or the sql backdoor firewall modules ")
            elif("Microsoft.Sql/servers/databases/*" in perm):
                self.logger.highlight("Current user has permission to run all sql database commands - consider running the sql db list ")
            

    def privs(self):
        # Grab user UPN
        logging.debug("Starting privs")
        if self.args.privs == '':
            upn_resp = subprocess.run(['az', 'ad', 'signed-in-user', 'show','--query', '{upn:userPrincipalName}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            upn_resp = subprocess.run(['az','ad', 'user', 'show', '--id', self.args.privs, '--query', '{upn:userPrincipalName}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


        try:
            upn_json_obj = json.loads(upn_resp.stdout.decode('utf-8'))
            upn = upn_json_obj['upn']
            logging.debug("upn {}".format(upn))
        except:
            self.logger.error("Current user has no subscriptions")
            return

        # GetCurrent users roles
        role_resp = subprocess.run(['az', 'role', 'assignment', 'list', '--assignee', upn, '--query', '[].{roleName:roleDefinitionName}'], stdout=subprocess.PIPE)
        try:
            role_json_obj = json.loads(role_resp.stdout.decode('utf-8'))
        except:
            self.logger.error("Current user has no subscriptions")
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

###############################################################################

    ######  #######  #####  ####### #     # ######   #####  ####### 
    #     # #       #     # #     # #     # #     # #     # #       
    #     # #       #       #     # #     # #     # #       #       
    ######  #####    #####  #     # #     # ######  #       #####   
    #   #   #             # #     # #     # #   #   #       #       
    #    #  #       #     # #     # #     # #    #  #     # #       
    #     # #######  #####  #######  #####  #     #  #####  ####### 

###############################################################################
###############################################################################
#
#
#
#
###############################################################################


    def rgroups(self):
        rgroup = subprocess.run(['az','group', 'list', '--query', '[].{name:name, location: location, id: id}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            rgroup_json = json.loads(rgroup.stdout.decode('utf-8'))
        except:
            self.logger.error("Current user has no subscriptions")
            return
        pprint.pprint(rgroup_json)


###############################################################################

                     #####      #####     #       
                    #     #    #     #    #       
                    #          #     #    #       
                     #####     #     #    #       
                          #    #   # #    #       
                    #     #    #    #     #       
                     #####      #### #    ####### 
                              
###############################################################################
###############################################################################
#
#
#
#
###############################################################################

    def sql_list(self):

        # Get server list
        sql_info = subprocess.run(['az', 'sql', 'server', 'list', '--query', '[].{fqdn:fullyQualifiedDomainName, name:name, rgrp: resourceGroup, admin_username:administratorLogin} '], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            sql_info_json = json.loads(sql_info.stdout.decode('utf-8'))
        except:
            self.logger.error("Current user has no SQL subscriptions")
            return
        pprint.pprint(sql_info_json)


    def sql_db_list(self):

        # Get server list
        sql_info = subprocess.run(['az', 'sql', 'server', 'list', '--query', '[].{name:name, rgrp: resourceGroup} '], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            sql_info_json = json.loads(sql_info.stdout.decode('utf-8'))
        except:
            self.logger.error("Current user has no SQL subscriptions")
            return
        
        servers = []
        rgrps = []
        for info in sql_info_json:
            servers.append(info['name'])
            rgrps.append(info['rgrp'])
            pprint.pprint(rgroup_json)

        # Get DBs
        for i in range(len(servers)):
            sql_info = subprocess.run(['az', 'sql', 'db', 'list', '--server', servers[i], '--resource-group', rgrps[i], '--query', '[].{collation:collation, name:name, location:location, dbId:databaseId}'], stdout=subprocess.PIPE)
            sql_info_json = json.loads(sql_info.stdout.decode('utf-8'))
            print(servers[i], "\n")
            pprint.pprint(sql_info_json)


###############################################################################

         #####  ####### ####### ######     #     #####  ####### 
        #     #    #    #     # #     #   # #   #     # #       
        #          #    #     # #     #  #   #  #       #       
         #####     #    #     # ######  #     # #  #### #####   
              #    #    #     # #   #   ####### #     # #       
        #     #    #    #     # #    #  #     # #     # #       
         #####     #    ####### #     # #     #  #####  ####### 

###############################################################################
###############################################################################
#
#
#
#
###############################################################################

    def storage_list(self):

        stg_list = subprocess.run(['az','storage', 'account', 'list', '--query', '[].{resource_group:resourceGroup, storage_types:primaryEndpoints}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stg_list_json = json.loads(stg_list.stdout.decode('utf-8'))
        except:
            self.logger.error("Current user has no Storage subscriptions")
            return
        pprint.pprint(stg_list_json)




###############################################################################

                    #     #          #     # 
                    #     #          ##   ## 
                    #     #          # # # # 
                    #     #          #  #  # 
                     #   #           #     # 
                      # #            #     # 
                       #             #     # 
                                       
###############################################################################
###############################################################################
#
#
#
#
###############################################################################

    def vm_list(self):

        # Get all vms in subscription
        if self.args.vm_list == '':
            vm_list = subprocess.run(['az','vm', 'list', '--query', '[].{name:name,os:storageProfile.osDisk.osType, username:osProfile.adminUsername, vm_size:hardwareProfile.vmSize, resource_group: resourceGroup}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                vm_list_json = json.loads(vm_list.stdout.decode('utf-8'))
            except:
                self.logger.error("Current user has no VM subscriptions")
                return
    
            vm_iplist = subprocess.run(['az','vm', 'list-ip-addresses', '--query', '[].{name:virtualMachine.name, privateIp:virtualMachine.network.privateIpAddresses, publicIp:virtualMachine.network.publicIpAddresses[].ipAddress}'], stdout=subprocess.PIPE)
            try:
                vm_iplist_json = json.loads(vm_iplist.stdout.decode('utf-8'))
            except:
                self.logger.error("Current user has no VM subscriptions")
                return

        else: # Get all vms in specified resource group
            vm_list = subprocess.run(['az','vm', 'list', '-g', self.args.vm_list, '--query', '[].{name:name,os:storageProfile.osDisk.osType, username:osProfile.adminUsername, vm_size:hardwareProfile.vmSize, resource_group: resourceGroup}'], stdout=subprocess.PIPE)
            try:
                vm_list_json = json.loads(vm_list.stdout.decode('utf-8'))
            except:
                self.logger.error("Current user has no VM subscriptions")
                return

            vm_iplist = subprocess.run(['az','vm', 'list-ip-addresses', '-g', self.args.vm_list, '--query', '[].{name:virtualMachine.name, privateIp:virtualMachine.network.privateIpAddresses, publicIp:virtualMachine.network.publicIpAddresses[].ipAddress}'], stdout=subprocess.PIPE)
            try:
                vm_iplist_json = json.loads(vm_iplist.stdout.decode('utf-8'))
            except:
                self.logger.error("Current user has no VM subscriptions")
                return


        for i in range(len(vm_list_json)):
            vm_list_json[i].update(vm_iplist_json[i])
        
        pprint.pprint(vm_list_json)


    def vmss_list(self):

        # Get list of vmss
        vmss_list = subprocess.run(['az','vmss', 'list', '--query', '[].{name:name, rgrp:resourceGroup}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            vmss_list_json = json.loads(vmss_list.stdout.decode('utf-8'))
        except:
            self.logger.error("Current user has no VM subscriptions")
            return

        for i in range(len(vmss_list_json)):
            # Get vmss info
            vmss_list = subprocess.run(['az','vmss', 'list', '--resource-group', vmss_list_json[i]['rgrp'], '--query', '[].{name:name, vmss_size:sku.name, os_distro:virtualMachineProfile.storageProfile.imageReference.offer,os_version:virtualMachineProfile.storageProfile.imageReference.sku, username:virtualMachineProfile.osProfile.adminUsername, rgrp: resourceGroup}'], stdout=subprocess.PIPE)
            vmss_list_json = json.loads(vmss_list.stdout.decode('utf-8'))
            pprint.pprint(vmss_list_json[i])
            # Get vmss IP
            vmss_iplist = subprocess.run(['az','vmss', 'list-instance-public-ips', '--resource-group', vmss_list_json[i]['rgrp'], '--name', vmss_list_json[i]['name'],  '--query', '[].{ipAddress:ipAddress}'], stdout=subprocess.PIPE)
            vmss_iplist_json = json.loads(vmss_iplist.stdout.decode('utf-8'))
            pprint.pprint(vmss_iplist_json)


###############################################################################

             #####     ######     #     # 
            #     #    #     #    ##    # 
            #          #     #    # #   # 
             #####     ######     #  #  # 
                  #    #          #   # # 
            #     #    #          #    ## 
             #####     #          #     # 

###############################################################################
###############################################################################
#
#
#
#
###############################################################################


    def spn_list(self):

        stg_list = subprocess.run(['az','ad', 'sp', 'list', '--all', '--query', '[].{appDisplayName:appDisplayName, appId:appId}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stg_list_json = json.loads(stg_list.stdout.decode('utf-8'))
        except:
            self.logger.error("Current user has no VM subscriptions")
            return
        pprint.pprint(stg_list_json)
