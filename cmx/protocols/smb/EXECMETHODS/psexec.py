#!/usr/bin/env python
#
#       Executes as SYSTEM
#
#
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# PSEXEC like functionality example using RemComSvc (https://github.com/kavika13/RemCom)
#
# Author:
#  beto (@agsolino)
#
# Reference for:
#  DCE/RPC and SMB.
import pdb
import sys
import os
import cmd
import logging
from threading import Thread, Lock
import argparse
import random
import string
import time
from six import PY3

from impacket.examples import logger
from impacket import version, smb
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport
from impacket.structure import Structure
from impacket.examples import remcomsvc, serviceinstall

from cmx.helpers.misc import gen_random_string
from cmx.servers.smb import CMXSMBServer
from cmx import config as cfg

OUTPUT_FILENAME = '__output'
BATCH_FILENAME  = 'execute.bat'
SMBSERVER_DIR   = './logs/'
DUMMY_SHARE     = 'TMP'


class RemComMessage(Structure):
    structure = (
        ('Command','4096s=""'),
        ('WorkingDir','260s=""'),
        ('Priority','<L=0x20'),
        ('ProcessID','<L=0x01'),
        ('Machine','260s=""'),
        ('NoWait','<L=0'),
    )

class RemComResponse(Structure):
    structure = (
        ('ErrorCode','<L=0'),
        ('ReturnCode','<L=0'),
    )

RemComSTDOUT         = "RemCom_stdout"
RemComSTDIN          = "RemCom_stdin"
RemComSTDERR         = "RemCom_stderr"

lock = Lock()



class PSEXEC:
    def __init__(self, host, port=445, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, kdcHost=None, serviceName=''):
        self.__username = username
        self.__password = password
        self.__host = host
        self.__port = port
        self.__command = 'cmd.exe'
        self.__path = None
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__exeFile = None
        self.__copyFile = None
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__serviceName = serviceName
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')


        #self.__retOutput = output
        #self.execute_fileless(command)
        #self.finish()
        #return self.__outputBuffer

    def execute(self, command, output=False):

        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % self.__host
        logging.debug('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(self.__host)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)

        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        #doStuff in impacket
        dce = rpctransport.get_dce_rpc()
        try:
            dce.connect()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical(str(e))
            sys.exit(1)

        global dialect
        dialect = rpctransport.get_smb_connection().getDialect()

        try:
            unInstalled = False
            s = rpctransport.get_smb_connection()

            # We don't wanna deal with timeouts from now on.
            s.setTimeout(100000)
            if self.__exeFile is None:
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_connection(), remcomsvc.RemComSvc(), self.__serviceName)
            else:
                try:
                    f = open(self.__exeFile)
                except Exception as e:
                    logging.critical(str(e))
                    sys.exit(1)
                installService = serviceinstall.ServiceInstall(rpctransport.get_smb_connection(), f)

            if installService.install() is False:
                return

            if self.__exeFile is not None:
                f.close()

            # Check if we need to copy a file for execution
            if self.__copyFile is not None:
                installService.copy_file(self.__copyFile, installService.getShare(), os.path.basename(self.__copyFile))
                # And we change the command to be executed to this filename
                self.__command = os.path.basename(self.__copyFile) + ' ' + self.__command

            tid = s.connectTree('IPC$')
            fid_main = self.openPipe(s,tid,r'\RemCom_communicaton',0x12019f)

            packet = RemComMessage()
            pid = os.getpid()

            packet['Machine'] = ''.join([random.choice(string.ascii_letters) for _ in range(4)])
            if self.__path is not None:
                packet['WorkingDir'] = self.__path
            packet['Command'] = command
            packet['ProcessID'] = pid

            s.writeNamedPipe(tid, fid_main, packet.getData())

            # Here we'll store the command we type so we don't print it back ;)
            # ( I know.. globals are nasty :P )
            global LastDataSent
            LastDataSent = ''

            # Create the pipes threads
            stdin_pipe = RemoteStdInPipe(rpctransport,
                                         r'\%s%s%d' % (RemComSTDIN, packet['Machine'], packet['ProcessID']),
                                         smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA, installService.getShare(),
                                         command)

            stdin_pipe.start()
            stdout_pipe = RemoteStdOutPipe(rpctransport,
                                           r'\%s%s%d' % (RemComSTDOUT, packet['Machine'], packet['ProcessID']),
                                           smb.FILE_READ_DATA)
            stdout_pipe.start()
            stderr_pipe = RemoteStdErrPipe(rpctransport,
                                           r'\%s%s%d' % (RemComSTDERR, packet['Machine'], packet['ProcessID']),
                                           smb.FILE_READ_DATA)
            stderr_pipe.start()

            # And we stay here till the end
            ans = s.readNamedPipe(tid,fid_main,8)
            #pdb.set_trace()

            if len(ans):
                retCode = RemComResponse(ans)

                logging.info("Process %s finished with ErrorCode: %d, ReturnCode: %d" % (
                self.__command, retCode['ErrorCode'], retCode['ReturnCode']))
            installService.uninstall()
            if self.__copyFile is not None:
                # We copied a file for execution, let's remove it
                s.deleteFile(installService.getShare(), os.path.basename(self.__copyFile))
            unInstalled = True
        except:
            print ('error')
            pass

        #read our result file - this executes in RemoteStdInPipe.run functions
        with open(cfg.TEST_PATH, 'r') as file:
            data = file.read()

        return data


    def openPipe(self, s, tid, pipe, accessMask):
        pipeReady = False
        tries = 50
        while pipeReady is False and tries > 0:
            try:
                s.waitNamedPipe(tid, pipe)
                pipeReady = True
            except:
                tries -= 1
                time.sleep(2)
                pass

        if tries == 0:
            raise Exception('Pipe not ready, aborting')

        fid = s.openFile(tid,pipe,accessMask, creationOption = 0x40, fileAttributes = 0x80)

        return fid


    def run(self, addr, dummy):
        """ starts interactive shell """
        logging.debug('inside PSEXEC.run')

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




class Pipes(Thread):
    def __init__(self, transport, pipe, permissions, share=None):
        Thread.__init__(self)
        self.server = 0
        self.transport = transport
        self.credentials = transport.get_credentials()
        self.tid = 0
        self.fid = 0
        self.share = share
        self.port = transport.get_dport()
        self.pipe = pipe
        self.permissions = permissions
        self.daemon = True


    def connectPipe(self):
        try:
            lock.acquire()
            global dialect
            self.server = SMBConnection(self.transport.get_smb_connection().getRemoteName(), self.transport.get_smb_connection().getRemoteHost(),
                                        sess_port=self.port, preferredDialect=dialect)

            user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials

            if self.transport.get_kerberos() is True:
                self.server.kerberosLogin(user, passwd, domain, lm, nt, aesKey, kdcHost=self.transport.get_kdcHost(), TGT=TGT, TGS=TGS)
            else:
                self.server.login(user, passwd, domain, lm, nt)
            lock.release()
            self.tid = self.server.connectTree('IPC$') 

            self.server.waitNamedPipe(self.tid, self.pipe)
            self.fid = self.server.openFile(self.tid,self.pipe,self.permissions, creationOption = 0x40, fileAttributes = 0x80)
            self.server.setTimeout(1000000)
        except:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error("Something wen't wrong connecting the pipes(%s), try again" % self.__class__)


class RemoteStdOutPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.readFile(self.tid,self.fid, 0, 1024)
            except:
                pass
            else:
                try:
                    global LastDataSent
                    if ans != LastDataSent:
                        sys.stdout.write(ans.decode('cp437'))
                        sys.stdout.flush()
                    else:
                        # Don't echo what I sent, and clear it up
                        LastDataSent = ''
                    # Just in case this got out of sync, i'm cleaning it up if there are more than 10 chars, 
                    # it will give false positives tho.. we should find a better way to handle this.
                    if LastDataSent > 10:
                        LastDataSent = ''
                except:
                    pass


class RemoteStdErrPipe(Pipes):
    def __init__(self, transport, pipe, permisssions):
        Pipes.__init__(self, transport, pipe, permisssions)

    def run(self):
        self.connectPipe()
        while True:
            try:
                ans = self.server.readFile(self.tid,self.fid, 0, 1024)
            except:
                pass
            else:
                try:
                    sys.stderr.write(str(ans))
                    sys.stderr.flush()
                except:
                    pass


class RemoteStdInPipe(Pipes):
    def __init__(self, transport, pipe, permisssions, share=None, command=''):
        self.shell = None
        self.command = command
        Pipes.__init__(self, transport, pipe, permisssions, share)

    def run(self):
        self.connectPipe()
        self.shell = RemoteShell(self.server, self.port, self.credentials, self.tid, self.fid, self.share, self.transport)
        #self.shell.cmdloop()

        #store OG stdout
        a, b, c = sys.stdout, sys.stdin, sys.stderr

        #switch stdout to our 'buffer'
        buff = open(cfg.TEST_PATH,"w")
        sys.stdout, sys.stdin, sys.stderr = buff, buff, buff

        self.shell.onecmd(self.command)

        # switch back to normal
        sys.stdout, sys.stdin, sys.stderr = a, b, c 
        buff.close()


class RemoteShell(cmd.Cmd):
    def __init__(self, server, port, credentials, tid, fid, share, transport):
        cmd.Cmd.__init__(self, False)
        self.prompt = '\x08'
        self.server = server
        self.transferClient = None
        self.tid = tid
        self.fid = fid
        self.credentials = credentials
        self.share = share
        self.port = port
        self.transport = transport
        self.intro = '[!] Press help for extra shell commands'

    def connect_transferClient(self):
        self.transferClient = SMBConnection('*SMBSERVER', self.server.getRemoteHost(), sess_port=self.port,
                                            preferredDialect=dialect)

        user, passwd, domain, lm, nt, aesKey, TGT, TGS = self.credentials

        if self.transport.get_kerberos() is True:
            self.transferClient.kerberosLogin(user, passwd, domain, lm, nt, aesKey,
                                              kdcHost=self.transport.get_kdcHost(), TGT=TGT, TGS=TGS)
        else:
            self.transferClient.login(user, passwd, domain, lm, nt)

    def do_help(self, line):
        print("""
 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 put {src_file, dst_path}   - uploads a local file to the dst_path RELATIVE to the connected share (%s)
 get {file}                 - downloads pathname RELATIVE to the connected share (%s) to the current local dir 
 ! {cmd}                    - executes a local shell cmd
""" % (self.share, self.share))
        self.send_data('\r\n', False)

    def do_shell(self, s):
        os.system(s)
        self.send_data('\r\n')

    def do_get(self, src_path):
        try:
            if self.transferClient is None:
                self.connect_transferClient()

            import ntpath
            filename = ntpath.basename(src_path)
            fh = open(filename,'wb')
            logging.info("Downloading %s\\%s" % (self.share, src_path))
            self.transferClient.getFile(self.share, src_path, fh.write)
            fh.close()
        except Exception as e:
            logging.critical(str(e))
            pass

        self.send_data('\r\n')

    def do_put(self, s):
        try:
            if self.transferClient is None:
                self.connect_transferClient()
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = '/'

            src_file = os.path.basename(src_path)
            fh = open(src_path, 'rb')
            f = dst_path + '/' + src_file
            pathname = f.replace('/','\\')
            logging.info("Uploading %s to %s\\%s" % (src_file, self.share, dst_path))
            if PY3:
                self.transferClient.putFile(self.share, pathname, fh.read)
            else:
                self.transferClient.putFile(self.share, pathname.decode(sys.stdin.encoding), fh.read)
            fh.close()
        except Exception as e:
            logging.error(str(e))
            pass

        self.send_data('\r\n')

    def do_lcd(self, s):
        if s == '':
            print(os.getcwd())
        else:
            os.chdir(s)
        self.send_data('\r\n')

    def emptyline(self):
        self.send_data('\r\n')
        return

    def default(self, line):
        if PY3:
            self.send_data(line.encode('cp437')+b'\r\n')
        else:
            self.send_data(line.decode(sys.stdin.encoding).encode('cp437')+'\r\n')

    def send_data(self, data, hideOutput = True):
        if hideOutput is True:
            global LastDataSent
            LastDataSent = data
        else:
            LastDataSent = ''
        self.server.writeFile(self.tid, self.fid, data)
