#!/usr/bin/env python3

####################################################################
#   context.py   -   Provides modules with a hook back into original thread
#   
#   Allows modules to utilze logger and access arguments
#   
# Class:
#   Context
#
# Class Functions:
#   -
#
####################################################################

import logging
from cmx import config as cfg

class Context:

    def __init__(self, db, logger, args):
        self.db = db
        self.log = logger
        self.log.debug = logging.debug
        self.log_folder_path = cfg.LOGS_PATH
        self.localip = None

        for key, value in vars(args).items():
            setattr(self, key, value)
