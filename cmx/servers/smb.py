#!/usr/bin/env python3

import threading
import logging
from sys import exit
from impacket import smbserver
from pathlib import Path
from impacket.ntlm import compute_lmhash, compute_nthash
from cmx import config as cfg


class CMXSMBServer(threading.Thread):

    def __init__(self, logger, share_name, share_path=str(cfg.TMP_PATH), listen_address='0.0.0.0', listen_port=445, verbose=False, username='', password='', hashes='', computer=''):
        try:
            threading.Thread.__init__(self)

            self.server = smbserver.SimpleSMBServer(listen_address, listen_port)
            self.server.addShare(share_name.upper(), share_path)
            if verbose: self.server.setLogFile('')
            self.server.setSMB2Support(True)   #TODO: This needs a check on what version the login used.

            # adding credentials incase the org has disabled anon smb access
            # password can be a list of passwords, we only gonna make this work if you pass 1 password for now...
            if password is not '':
                lmhash = compute_lmhash(password[0])
                nthash = compute_nthash(password[0])
            else:
                lmhash, nthash = hashes.split(':')
            
            # username can be a list of users, we only gonna make this work if you pass 1 user for now...
            self.server.addCredential(username[0], 0, lmhash, nthash)
            self.server.addCredential(computer, 1, '', '')

            # Here you can set a custom SMB challenge in hex format, If empty defaults to '4141414141414141'
            # e.g. server.setSMBChallenge('12345678abcdef00')
            #self.server.setSMBChallenge('') 

        except Exception as e:
            errno, message = e.args
            if errno == 98 and message == 'Address already in use':
                logger.error('Error starting SMB server on port 445: the port is already in use')
            else:
                logger.error('Error starting SMB server on port 445: {}'.format(message))
                exit(1)

    def addShare(self, share_name, share_path):
        self.server.addShare(share_name, share_path)

    def run(self):
        try:
            self.server.start()
        except:
            pass
#need to implement 
    def shutdown(self):
        #self._Thread__stop()
        # Previously was killing threads. Updated to only show if threads remain, havent seent any yet..?
        for thread in threading.enumerate():
            if thread.isAlive():
                try:
                    logger.debug("thread is alive: {}".format(thread.get_ident()))
                except:
                    pass
