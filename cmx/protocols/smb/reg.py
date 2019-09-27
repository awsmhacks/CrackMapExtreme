#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Remote registry manipulation tool.
#              The idea is to provide similar functionality as the REG.EXE Windows utility.
#
#
# Author:
#  Manuel Porto (@manuporto)
#  Alberto Solino (@agsolino)
#
# Reference for: [MS-RRP]
#

from __future__ import division
from __future__ import print_function
import argparse
import codecs
import logging
import sys
import time
from struct import unpack

from impacket import version
from impacket.dcerpc.v5 import transport, rrp, scmr, rpcrt
from impacket.examples import logger
from impacket.system_errors import ERROR_NO_MORE_ITEMS
from impacket.structure import hexdump
from impacket.smbconnection import SMBConnection
from cmx.logger import CMXLogAdapter


class RemoteOperations:
    def __init__(self, smbConnection, doKerberos, kdcHost=None):
        self.__smbConnection = smbConnection
        self.__smbConnection.setTimeout(5 * 60)
        self.__serviceName = 'RemoteRegistry'
        self.__stringBindingWinReg = r'ncacn_np:445[\pipe\winreg]'
        self.__rrp = None
        self.__regHandle = None

        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost

        self.__disabled = False
        self.__shouldStop = False
        self.__started = False

        self.__stringBindingSvcCtl = r'ncacn_np:445[\pipe\svcctl]'
        self.__scmr = None

    def getRRP(self):
        return self.__rrp

    def __connectSvcCtl(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingSvcCtl)
        rpc.set_smb_connection(self.__smbConnection)
        self.__scmr = rpc.get_dce_rpc()
        self.__scmr.connect()
        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)

    def connectWinReg(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingWinReg)
        rpc.set_smb_connection(self.__smbConnection)
        self.__rrp = rpc.get_dce_rpc()
        self.__rrp.connect()
        self.__rrp.bind(rrp.MSRPC_UUID_RRP)

    def __checkServiceStatus(self):
        # Open SC Manager
        ans = scmr.hROpenSCManagerW(self.__scmr)
        self.__scManagerHandle = ans['lpScHandle']
        # Now let's open the service
        ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__serviceName)
        self.__serviceHandle = ans['lpServiceHandle']
        # Let's check its status
        ans = scmr.hRQueryServiceStatus(self.__scmr, self.__serviceHandle)
        if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            logging.info('Service %s is in stopped state' % self.__serviceName)
            self.__shouldStop = True
            self.__started = False
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            logging.debug('Service %s is already running' % self.__serviceName)
            self.__shouldStop = False
            self.__started = True
        else:
            raise Exception('Unknown service state 0x%x - Aborting' % ans['CurrentState'])

        # Let's check its configuration if service is stopped, maybe it's disabled :s
        if self.__started is False:
            ans = scmr.hRQueryServiceConfigW(self.__scmr, self.__serviceHandle)
            if ans['lpServiceConfig']['dwStartType'] == 0x4:
                logging.info('Service %s is disabled, enabling it' % self.__serviceName)
                self.__disabled = True
                scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType=0x3)
            logging.info('Starting service %s' % self.__serviceName)
            scmr.hRStartServiceW(self.__scmr, self.__serviceHandle)
            time.sleep(1)

    def enableRegistry(self):
        self.__connectSvcCtl()
        self.__checkServiceStatus()
        self.connectWinReg()

    def __restore(self):
        # First of all stop the service if it was originally stopped
        if self.__shouldStop is True:
            logging.info('Stopping service %s' % self.__serviceName)
            scmr.hRControlService(self.__scmr, self.__serviceHandle, scmr.SERVICE_CONTROL_STOP)
        if self.__disabled is True:
            logging.info('Restoring the disabled state for service %s' % self.__serviceName)
            scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType=0x4)

    def finish(self):
        self.__restore()
        if self.__rrp is not None:
            self.__rrp.disconnect()
        if self.__scmr is not None:
            self.__scmr.disconnect()


class RegHandler:
    def __init__(self, username, password, domain, logger, options):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__options = options
        self.__action = options.action.upper()
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__kdcHost = options.dc_ip
        self.__smbConnection = None
        self.__remoteOps = None
        self.logger = logger

        # It's possible that this is defined somewhere, but I couldn't find where
        self.__regValues = {0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY', 4: 'REG_DWORD',
                            5: 'REG_DWORD_BIG_ENDIAN', 6: 'REG_LINK', 7: 'REG_MULTI_SZ', 11: 'REG_QWORD'}

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')


    def connect(self, remoteName, remoteHost):
        self.__smbConnection = SMBConnection(remoteName, remoteHost, sess_port=int(self.__options.port))

        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)


    def run(self, remoteName, remoteHost):
        self.connect(remoteName, remoteHost)
        self.__remoteOps = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)

        try:
            self.__remoteOps.enableRegistry()
        except Exception as e:
            logging.debug(str(e))
            logging.warning('Cannot check RemoteRegistry status. Hoping it is started...')
            self.__remoteOps.connectWinReg()

        try:
            dce = self.__remoteOps.getRRP()

            if self.__action == 'QUERY':
                self.query(dce, self.__options.keyName)
            elif self.__action == 'ENABLEUAC':
                self.enableUAC(dce)
            elif self.__action == 'CHECKUAC':
                self.checkUAC(dce)
            else:
                logging.error('Method %s not implemented yet!' % self.__action)

        except (Exception, KeyboardInterrupt) as e:
            logging.critical(str(e))
        finally:
            if self.__remoteOps:
                self.__remoteOps.finish()


    def query(self, dce, keyName):
        # Let's strip the root key
        try:
            rootKey = keyName.split('\\')[0]
            subKey = '\\'.join(keyName.split('\\')[1:])
        except Exception:
            raise Exception('Error parsing keyName %s' % keyName)

        if rootKey.upper() == 'HKLM':
            ans = rrp.hOpenLocalMachine(dce)
        elif rootKey.upper() == 'HKU':
            ans = rrp.hOpenCurrentUser(dce)
        elif rootKey.upper() == 'HKCR':
            ans = rrp.hOpenClassesRoot(dce)
        else:
            raise Exception('Invalid root key %s ' % rootKey)

        hRootKey = ans['phKey']

        ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey,
                                   samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS | rrp.KEY_QUERY_VALUE)

        if self.__options.v:
            print(keyName)
            value = rrp.hBaseRegQueryValue(dce, ans2['phkResult'], self.__options.v)
            print('\t' + self.__options.v + '\t' + self.__regValues.get(value[0], 'KEY_NOT_FOUND') + '\t', str(value[1]))
        elif self.__options.ve:
            print(keyName)
            value = rrp.hBaseRegQueryValue(dce, ans2['phkResult'], '')
            print('\t' + '(Default)' + '\t' + self.__regValues.get(value[0], 'KEY_NOT_FOUND') + '\t', str(value[1]))
        elif self.__options.s:
            self.__print_all_subkeys_and_entries(dce, subKey + '\\', ans2['phkResult'], 0)
        else:
            print(keyName)
            self.__print_key_values(dce, ans2['phkResult'])
            i = 0
            while True:
                try:
                    key = rrp.hBaseRegEnumKey(dce, ans2['phkResult'], i)
                    print(keyName + '\\' + key['lpNameOut'][:-1])
                    i += 1
                except Exception:
                    break
                    # ans5 = rrp.hBaseRegGetVersion(rpc, ans2['phkResult'])
                    # ans3 = rrp.hBaseRegEnumKey(rpc, ans2['phkResult'], 0)

    def __print_key_values(self, rpc, keyHandler):
        i = 0
        while True:
            try:
                ans4 = rrp.hBaseRegEnumValue(rpc, keyHandler, i)
                lp_value_name = ans4['lpValueNameOut'][:-1]
                if len(lp_value_name) == 0:
                    lp_value_name = '(Default)'
                lp_type = ans4['lpType']
                lp_data = b''.join(ans4['lpData'])
                print('\t' + lp_value_name + '\t' + self.__regValues.get(lp_type, 'KEY_NOT_FOUND') + '\t', end=' ')
                self.__parse_lp_data(lp_type, lp_data)
                i += 1
            except rrp.DCERPCSessionError as e:
                if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                    break

    def __print_all_subkeys_and_entries(self, rpc, keyName, keyHandler, index):
        index = 0
        while True:
            try:
                subkey = rrp.hBaseRegEnumKey(rpc, keyHandler, index)
                index += 1
                ans = rrp.hBaseRegOpenKey(rpc, keyHandler, subkey['lpNameOut'],
                                          samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS)
                newKeyName = keyName + subkey['lpNameOut'][:-1] + '\\'
                print(newKeyName)
                self.__print_key_values(rpc, ans['phkResult'])
                self.__print_all_subkeys_and_entries(rpc, newKeyName, ans['phkResult'], 0)
            except rrp.DCERPCSessionError as e:
                if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                    break
            except rpcrt.DCERPCException as e:
                if str(e).find('access_denied') >= 0:
                    logging.error('Cannot access subkey %s, bypassing it' % subkey['lpNameOut'][:-1])
                    continue
                elif str(e).find('rpc_x_bad_stub_data') >= 0:
                    logging.error('Fault call, cannot retrieve value for %s, bypassing it' % subkey['lpNameOut'][:-1])
                    return
                raise

    @staticmethod
    def __parse_lp_data(valueType, valueData):
        try:
            if valueType == rrp.REG_SZ or valueType == rrp.REG_EXPAND_SZ:
                if type(valueData) is int:
                    print('NULL')
                else:
                    print("%s" % (valueData.decode('utf-16le')[:-1]))
            elif valueType == rrp.REG_BINARY:
                print('')
                hexdump(valueData, '\t')
            elif valueType == rrp.REG_DWORD:
                print("0x%x" % (unpack('<L', valueData)[0]))
            elif valueType == rrp.REG_QWORD:
                print("0x%x" % (unpack('<Q', valueData)[0]))
            elif valueType == rrp.REG_NONE:
                try:
                    if len(valueData) > 1:
                        print('')
                        hexdump(valueData, '\t')
                    else:
                        print(" NULL")
                except:
                    print(" NULL")
            elif valueType == rrp.REG_MULTI_SZ:
                print("%s" % (valueData.decode('utf-16le')[:-2]))
            else:
                print("Unknown Type 0x%x!" % valueType)
                hexdump(valueData)
        except Exception as e:
            logging.debug('Exception thrown when printing reg value %s', str(e))
            print('Invalid data')
            pass


    def enableUAC(self, dce):
        # 
        try:
            ans = rrp.hOpenLocalMachine(dce)
            regHandle  = ans['phKey']
        except Exception as e:
            logging.debug('Exception thrown when hOpenLocalMachine: %s', str(e))
            return


        try:
            resp = rrp.hBaseRegCreateKey(dce, regHandle , 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
            keyHandle = resp['phkResult']
        except Exception as e:
            logging.debug('Exception thrown when hBaseRegCreateKey: %s', str(e))
            return

        # EnableLUA
        try:
            resp = rrp.hBaseRegSetValue(dce, keyHandle, 'EnableLUA\x00',  rrp.REG_DWORD, 0)
            self.logger.highlight('EnableLUA Key Set!')
        except Exception as e:
            logging.debug('Exception thrown when hBaseRegSetValue EnableLUA: %s', str(e))
            self.logger.error('Could not set EnableLUA Key')
            pass

        # LocalAccountTokenFilterPolicy
        try:
            resp = rrp.hBaseRegSetValue(dce, keyHandle, 'LocalAccountTokenFilterPolicy\x00',  rrp.REG_DWORD, 1)
            self.logger.highlight('LocalAccountTokenFilterPolicy Key Set!')
        except Exception as e:
            logging.debug('Exception thrown when hBaseRegSetValue LocalAccountTokenFilterPolicy: %s', str(e))
            self.logger.error('Could not set LocalAccountTokenFilterPolicy Key')
            return


    def checkUAC(self, dce):
        # 
        try:
            ans = rrp.hOpenLocalMachine(dce)
            regHandle  = ans['phKey']
        except Exception as e:
            logging.debug('Exception thrown when hOpenLocalMachine: %s', str(e))
            return

        self.logger.highlight('UAC Status:')

        try:
            resp = rrp.hBaseRegOpenKey(dce, regHandle , 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System')
            keyHandle = resp['phkResult']
        except Exception as e:
            logging.debug('Exception thrown when hBaseRegOpenKey: %s', str(e))
            return

        try:
            dataType, lua_uac_value = rrp.hBaseRegQueryValue(dce, keyHandle, 'EnableLUA')
        except Exception as e:
            logging.debug('Exception thrown when hBaseRegQueryValue: %s', str(e))
            self.logger.highlight('     enableLua key does not exist!')
            lua_uac_value = 3
            pass

        try:
            dataType, latfp_uac_value = rrp.hBaseRegQueryValue(dce, keyHandle, 'LocalAccountTokenFilterPolicy')
        except Exception as e:
            logging.debug('Exception thrown when hBaseRegQueryValue: %s', str(e))
            self.logger.highlight('     LocalAccountTokenFilterPolicy key does not exist!')
            latfp_uac_value = 3
            pass

        if lua_uac_value == 1:
            #print('enableLua = 1')
            self.logger.highlight('    enableLua = 1') 
        elif lua_uac_value == 0:
            #print('enableLua = 0')
            self.logger.highlight('    enableLua = 0')

        if latfp_uac_value == 1:
            #print('enableLua = 1')
            self.logger.highlight('    LocalAccountTokenFilterPolicy = 1') 
        elif latfp_uac_value == 0:
            #print('enableLua = 0')
            self.logger.highlight('    LocalAccountTokenFilterPolicy = 0')



