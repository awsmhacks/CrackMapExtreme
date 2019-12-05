#!/usr/bin/env python3

####################################################################
#   first_run.py
#   Runs the first time cmx is launched.
#   Reads configurations defined in config.py
#
#   Creates folder structure, sets up database, creates keys for https coms 
#   
#
#
# Classes:
#   -
#
# Non-Class Functions:
#   first_run_setup
#
####################################################################

import os
import sqlite3
import shutil
import cmx
import errno
from cmx.loaders.protocol_loader import protocol_loader
from subprocess import check_output, PIPE
from sys import exit
from cmx import config as cfg

def first_run_setup(logger):

    if not cfg.TMP_PATH.is_dir():
        cfg.TMP_PATH.mkdir(parents=True, exist_ok=True)

    if not cfg.AZ_PATH.is_dir():
        cfg.AZ_PATH.mkdir(parents=True, exist_ok=True)

    if not cfg.CMX_HOME.is_dir():
        logger.announce('First time use detected')
        logger.announce('Creating home directory structure. Files will be located in {}'.format(cfg.CMX_HOME))
        cfg.CMX_HOME.mkdir(parents=True, exist_ok=True)

    folders = ['logs', 'modules', 'protocols', 'workspaces', 'obfuscated_scripts']
    for folder in folders:
        if not (cfg.CMX_HOME / folder).is_dir():
            (cfg.CMX_HOME / folder).mkdir(parents=True, exist_ok=True)

    if not (cfg.WS_PATH / 'default').is_dir():
        logger.announce('Creating default workspace')
        (cfg.WS_PATH / 'default').mkdir(parents=True, exist_ok=True)

    p_loader = protocol_loader()
    protocols = p_loader.get_protocols()
    for protocol in list(protocols.keys()):
        try:
            protocol_object = p_loader.load_protocol(protocols[protocol]['dbpath'])
        except KeyError:
            continue

        proto_db_path = cfg.WS_PATH / 'default' / protocol
        proto_db_path = proto_db_path.with_suffix('.db')

        if not proto_db_path.is_file():
            logger.announce('Initializing {} protocol database'.format(protocol.upper()))
            conn = sqlite3.connect(proto_db_path)
            c = conn.cursor()

            # try to prevent some of the weird sqlite I/O errors
            c.execute('PRAGMA journal_mode = OFF')
            c.execute('PRAGMA foreign_keys = 1')

            getattr(protocol_object, 'database').db_schema(c)

            # commit the changes and close everything off
            conn.commit()
            conn.close()

    if not cfg.CERT_PATH.is_file():
        logger.announce('Generating SSL certificate')
        try:
            check_output(['openssl', 'help'], stderr=PIPE)
        except OSError as e:
            if e.errno == errno.ENOENT:
                logger.error('OpenSSL command line utility is not installed, could not generate certificate')
                exit(1)
            else:
                logger.error('Error while generating SSL certificate: {}'.format(e))
                exit(1)

        os.system('openssl req -new -x509 -keyout {k} -out {p} -days 365 -nodes -subj "/C=US"'.format(k=cfg.KEY_PATH,p=cfg.CERT_PATH))
