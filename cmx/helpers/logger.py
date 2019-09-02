#!/usr/bin/env python3

from termcolor import colored
from colorama import init #for the windoze
from cmx import config as cfg

init()  #Doing this so we dont have to switch out all the termcolor calls for colorama

def write_log(data, log_name):
    logfile = cfg.LOGS_PATH / log_name
    with open(logfile, mode='wt') as log_output:
        log_output.write(data)

def highlight(text, color='blue'):
    if color == 'purple':
        return u'{}'.format(colored(text, 'magenta', attrs=['bold']))
    else:
        return u'{}'.format(colored(text, color, attrs=['bold']))
#grey
#red
#green
#yellow
#blue
#magenta
#cyan
#white
