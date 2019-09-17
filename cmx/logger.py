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
    This class is used as the logger for CMX. Extending the logging abilities with 
    colors and attributes(bold).

    The following display regardless of verbosity/debug:
        info, error, success, results, highlight.
    Depending on the context a log function was called from, results may vary. 
    Check the function definition for more info
 
    info -      Used to display general output 
    error -     Used to display an error occured during execution over a connection
    success -   Used to display a successful authentication or connection
    highlight - Used to display results in yellow
    results -   Used for result outputs that have long lines


    The following display depending on verbosity level -v, -vv, -v --verbose -vvvv:
    v1 -  Used to inform the user of an execution or action being launched 
    v2 -  entry and exit of functions
    v3 -  variable values
    v4 -  info overload / stack traces at exceptions


    Debug only shows with -D or --debug enabled
    debug -     Used for debugging in -D --debug mode


    Examples:

    announce - self.logger.announce("Info Msg") 
        Aug.26.19 10:40:39  SMB   10.10.33.125:445   WIN10E  [*] Info Msg

    error - self.logger.error("Error Msg")
        Aug.26.19 10:40:39  SMB   10.10.33.125:445   WIN10E  [-] Error Msg

    success - self.logger.success("Success Msg")
        Aug.26.19 10:40:39  SMB   10.10.33.125:445   WIN10E  [+] Success Msg

    highlight - self.logger.highlight("Highlight Msg")
        Aug.26.19 10:40:39  SMB   10.10.33.125:445   WIN10E  Highlight Msg

    results - self.logger.results("Results Msg")
        Aug.26.19 10:33:02  Results Msg


    v1 - self.logger.v1("Starting Function Execution Msg")
        Aug.26.19 10:33:02     [!] Starting Function Execution Msg [!]

    v2 - self.logger.v2("Entering Function Execution Msg")
        Aug.26.19 10:33:02     [!!] Level 2 Function Execution Msg [!!]

    v3 - self.logger.v3("Variable values Msg")
        Aug.26.19 10:33:02     [!!!] Entering Function Execution Msg

    v4 - self.logger.v4("Info dump")
        Aug.26.19 10:33:02     [!!!!] Info dump



    Debug only shows with -D or --debug enabled
    Debug comes only after cmx ~~ i.e. "cmx -D smb 10.10.10.10 

    debug - self.logger.debug("debug Msg")
        DEBUG debug Msg


    self.logger.announce("Info thing") 
    self.logger.error("Error thing")
    self.logger.debug("Debug thing")
    self.logger.success("Success thing")
    self.logger.results("Results thing")
    self.logger.highlight("Highlight thing")

    '''

    # For Impacket's TDS library
    message = ''

    def __init__(self, logger_name='CMX', extra=None):
        self.logger = logging.getLogger(logger_name)
        self.extra = extra
        self.hostname = ''


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

        #If the logger is being called from a protocol, with or without a module
        if 'module' in self.extra.keys():
            module_name = colored(self.extra['module'], 'cyan', attrs=['bold'])
        else:
            module_name = colored(self.extra['protocol'], 'blue', attrs=['bold'])
     
        #Make it purdy
        #reminder: colored adds 8chars before, 6chars after items - because hex
        host_ip = colored(self.extra['host'], 'white') 
        host_port = colored(self.extra['port'], 'white')
        host_name = colored(self.hostname, 'magenta')

        return u'{:<19} {:<24} {:<15}:{:<13} {:<16} {}'.format(datetime.datetime.now().strftime("%b.%d.%y %H:%M:%S"),
                                                    module_name,
                                                    host_ip,
                                                    host_port,
                                                    host_name,
                                                    msg), kwargs

    def announce(self, msg, *args, **kwargs):
        """[*] Displays information to user
        
        If called from an operation inside a protocol ouputs 
            Aug.26.19 10:40:39  SMB   10.10.33.125:445   WIN10E  [*] <Info Msg>
        
        When used to list information, such as when used to list modules
            [*] Module           Module Description 
        """

        try:
            if 'protocol' in self.extra.keys() and not called_from_cmd_args():
                return
        except AttributeError:
            pass

        msg, kwargs = self.process(u'{} {}'.format(colored('[*]', 'blue', attrs=['bold']), msg), kwargs)
        self.logger.info(msg, *args, **kwargs)


    def error(self, msg, *args, **kwargs):
        """[-] Error messages that need to be relayed to a user due to failures

        Called from anywhere
            Aug.26.19 10:51:42  SMB         10.10.33.125:445  WIN10E  [-] <error msg>
        """

        msg = u'{}'.format(colored(msg, 'red'))
        msg, kwargs = self.process(u'{} {}'.format(colored('[-]', 'red', attrs=['bold']), msg), kwargs)
        self.logger.error(msg, *args, **kwargs)


    def debug(self, msg, *args, **kwargs):
        """DEBUG debug messages only output during -D or --debug and prepend no special formatting
        
        Called from anywhere
            DEBUG <msg>
        """
        pass


    def success(self, msg, *args, **kwargs):
        """[+] Success messages inform the user of a successful authentication 

        If called from an operation inside a protocol ouputs:
            Aug.26.19 10:40:39  SMB   10.10.33.125:445   WIN10E  [+] Success Msg

        Used to also show successful events occuring locally, such as clearing obfuscated scripts         
            [+] Cleared cached obfuscated PowerShell scripts
        """
        try:
            if 'protocol' in self.extra.keys() and not called_from_cmd_args():
                return
        except AttributeError:
            pass

        msg, kwargs = self.process(u'{} {}'.format(colored("[+]", 'green', attrs=['bold']), msg), kwargs)
        self.logger.info(msg, *args, **kwargs)


    def announced(self, msg, *args, **kwargs):
        """ [!] Announcements are broadcast statements informing the user of an operation start/complete

        Called from anywhere
            Aug.26.19 11:25:45         [!] <Announcement Message> [!]
        """
        return
        msg, kwargs = u'{:<26} {:<13} {} {}'.format(datetime.datetime.now().strftime("%b.%d.%y %H:%M:%S"),
                                        colored("[!]", 'green', 'on_grey', attrs=['bold']), 
                                        colored(msg, 'green','on_grey'),
                                        colored("[!]", 'green', 'on_grey', attrs=['bold'])), kwargs

        self.logger.announce(msg, *args, **kwargs)

    def results(self, msg, *args, **kwargs):
        """[!] Results are used for information returned from an operation that is to long for success

        Called from anywhere
            Aug.26.19 11:25:45  <Results message>
        """

        msg, kwargs = u'{:<19} {}'.format(datetime.datetime.now().strftime("%b.%d.%y %H:%M:%S"), 
                                        colored(msg, 'yellow', attrs=['bold'])), kwargs

        self.logger.info(msg, *args, **kwargs)


    def highlight(self, msg, *args, **kwargs):
        """
        """
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


def setup_verbose_logger(loglevel=0):
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
