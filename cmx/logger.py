#!/usr/bin/env python3

from cmx.helpers.misc import called_from_cmd_args
from cmx import config as cfg
from termcolor import colored
from colorama import init
import datetime
import logging
import sys
import re

import pdb


init()  #Doing this so we dont have to switch out all the termcolor calls for colorama

#The following hooks the FileHandler.emit function to remove ansi chars before logging to a file
#There must be a better way of doing this, but this way we might save some penguins!
ansi_escape = re.compile(r'\x1b[^m]*m')

def antiansi_emit(self, record):

    if self.stream is None:
        self.stream = self._open()

    record.msg = ansi_escape.sub('', record.message)
    logging.StreamHandler.emit(self, record)

logging.FileHandler.emit = antiansi_emit

####################################################################

class CMXLogAdapter(logging.LoggerAdapter):
    '''
    This class is designed to look like a Logger, so that you can call 
    debug(), info(), warning(), error(), exception(), critical() and log()
    '''

    # For Impacket's TDS library
    message = ''

    def __init__(self, logger_name='CMX', extra=None):
        self.logger = logging.getLogger(logger_name)
        self.extra = extra
        if self.extra['hostname']:
            self.hostname = self.extra['hostname']  
        else:
        self.hostname = self.extra['host']

    def process(self, msg, kwargs):
        if self.extra is None:
            return u'{}'.format(msg), kwargs

        if 'module' in self.extra.keys():
            if len(self.extra['module']) > 8:
                self.extra['module'] = self.extra['module'][:8] + '...'

        #If the logger is being called when hooking the 'options' module function
        if len(self.extra) == 1 and ('module' in self.extra.keys()):
            return u'{:<65} {}'.format(colored(self.extra['module'], 'cyan', attrs=['bold']), msg), kwargs

        #If the logger is being called from a CMXServer
        if len(self.extra) == 2 and ('module' in self.extra.keys()) and ('host' in self.extra.keys()):
            return u'{:<19} {:<24} {:<20} {}'.format(datetime.datetime.now().strftime("%b.%d.%y %H:%M:%S"),
                                                colored(self.extra['module'], 'cyan', attrs=['bold']),
                                                self.extra['host'], msg), kwargs

        #If the logger is being called from a protocol
        if 'module' in self.extra.keys():
            module_name = colored(self.extra['module'], 'cyan', attrs=['bold'])
        else:
            module_name = colored(self.extra['protocol'], 'blue', attrs=['bold'])
     
        #Make it purdy
        host_ip = colored(self.extra['host'], 'white') #colored adds 8chars before, 6chars after items - because hex
        host_port = colored(self.extra['port'], 'white')
        host_name = colored(self.extra['hostname'], 'magenta')

        return u'{:<19} {:<24} {:<15}:{:<13} {:<16} {}'.format(datetime.datetime.now().strftime("%b.%d.%y %H:%M:%S"),
                                                    module_name,
                                                    host_ip,
                                                    host_port,
                                                    self.host_name,
                                                    msg), kwargs

    def info(self, msg, *args, **kwargs):
        try:
            if 'protocol' in self.extra.keys() and not called_from_cmd_args():
                return
        except AttributeError:
            pass

        msg, kwargs = self.process(u'{} {}'.format(colored('[*]', 'blue', attrs=['bold']), msg), kwargs)
        self.logger.info(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        msg = u'{}'.format(colored(msg, 'red'))
        msg, kwargs = self.process(u'{} {}'.format(colored('[-]', 'red', attrs=['bold']), msg), kwargs)
        self.logger.error(msg, *args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        pass

    def success(self, msg, *args, **kwargs):
        try:
            if 'protocol' in self.extra.keys() and not called_from_cmd_args():
                return
        except AttributeError:
            pass

        msg, kwargs = self.process(u'{} {}'.format(colored("[+]", 'green', attrs=['bold']), msg), kwargs)
        self.logger.info(msg, *args, **kwargs)

    def announce(self, msg, *args, **kwargs):

        msg, kwargs = u'{:<26} {:<13} {} {}'.format(datetime.datetime.now().strftime("%b.%d.%y %H:%M:%S"),
                                        colored("[!]", 'green', 'on_grey', attrs=['bold']), 
                                        colored(msg, 'green','on_grey'),
                                        colored("[!]", 'green', 'on_grey', attrs=['bold'])), kwargs

        self.logger.info(msg, *args, **kwargs)

    def results(self, msg, *args, **kwargs):

        msg, kwargs = u'{:<19} {}'.format(datetime.datetime.now().strftime("%b.%d.%y %H:%M:%S"), 
                                        colored(msg, 'yellow', attrs=['bold'])), kwargs

        self.logger.info(msg, *args, **kwargs)


    def highlight(self, msg, *args, **kwargs):
        try:
            if 'protocol' in self.extra.keys() and not called_from_cmd_args():
                return
        except AttributeError:
            pass

        msg, kwargs = self.process(u'{}'.format(colored(msg, 'yellow', attrs=['bold'])), kwargs)
        self.logger.info(msg, *args, **kwargs)

    # For Impacket's TDS library
    def logMessage(self,message):
        CMXLogAdapter.message += message.strip().replace('NULL', '') + '\n'

    def getMessage(self):
        out = CMXLogAdapter.message
        CMXLogAdapter.message = ''
        return out

def setup_debug_logger():
    debug_output_string = "{} %(message)s".format(colored('DEBUG', 'magenta', attrs=['bold']))
    formatter = logging.Formatter(debug_output_string)
    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.propagate = False
    root_logger.addHandler(streamHandler)
    #root_logger.addHandler(fileHandler)
    root_logger.setLevel(logging.DEBUG)
    return root_logger

def setup_logger(level=logging.INFO, log_to_file=False, log_prefix=None, logger_name='CMX'):

    formatter = logging.Formatter("%(message)s")

    if log_to_file:
        if not log_prefix:
            log_prefix = 'log'

        log_filename = '{}_{}.log'.format(log_prefix.replace('/', '_'), datetime.now().strftime('%Y-%m-%d'))
        fileHandler = logging.FileHandler('./logs/{}'.format(log_filename))
        fileHandler.setFormatter(formatter)

    streamHandler = logging.StreamHandler(sys.stdout)
    streamHandler.setFormatter(formatter)

    cmx_logger = logging.getLogger(logger_name)
    cmx_logger.propagate = False
    cmx_logger.addHandler(streamHandler)

    if log_to_file:
        cmx_logger.addHandler(fileHandler)

    cmx_logger.setLevel(level)

    return cmx_logger
