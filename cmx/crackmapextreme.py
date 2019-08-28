#!/usr/bin/env python3

from gevent.pool import Pool
from cmx.logger import setup_logger, setup_debug_logger, CMXLogAdapter
from cmx.helpers.logger import highlight
from cmx.helpers.misc import identify_target_file
from cmx.parsers.ip import parse_targets
from cmx.cli import gen_cli_args
from cmx.loaders.protocol_loader import protocol_loader
from cmx.loaders.module_loader import module_loader
from cmx.servers.http import CMXServer
from cmx.first_run import first_run_setup
from cmx.context import Context
from cmx import config as cfg
from pprint import pformat
from pathlib import Path
import cmx.helpers.powershell as powershell
import shutil
import sqlite3
import os
import sys
import logging

def main():

    setup_logger()
    logger = CMXLogAdapter()
    first_run_setup(logger)

    args = gen_cli_args()

    module = None
    module_server = None
    targets = []
    server_port_dict = {'http': 80, 'https': 443, 'smb': 445}
    current_workspace = cfg.WORKSPACE

    if args.verbose:
        setup_debug_logger()

    logging.debug('Passed args:\n' + pformat(vars(args)))

    if hasattr(args, 'password') and args.password:
        for passw in args.password:
            if Path(passw).is_file():   #If it was a file passed in
                args.password.remove(passw)
                args.password.append(open(passw, 'r'))

    elif hasattr(args, 'hash') and args.hash:
        for ntlm_hash in args.hash:
            if Path(ntlm_hash).is_file():   #If it was a file passed in
                args.hash.remove(ntlm_hash)
                args.hash.append(open(ntlm_hash, 'r'))

    if hasattr(args, 'username') and args.username:
        for user in args.username:
            if Path(user).is_file():    #If it was a file passed in
                args.username.remove(user)
                args.username.append(open(user, 'r'))

    if hasattr(args, 'cred_id') and args.cred_id:
        for cred_id in args.cred_id:
            if '-' in str(cred_id):
                start_id, end_id = cred_id.split('-')
                try:
                    for n in range(int(start_id), int(end_id) + 1):
                        args.cred_id.append(n)
                    args.cred_id.remove(cred_id)
                except Exception as e:
                    logger.error('Error parsing database credential id: {}'.format(e))
                    sys.exit(1)

    if hasattr(args, 'target') and args.target:
        for target in args.target:
            if Path(target).is_file():   #If it was a file passed in
                target_file_type = identify_target_file(target)
                if target_file_type == 'nmap':
                    targets.extend(parse_nmap_xml(target, args.protocol))
                elif target_file_type == 'nessus':
                    targets.extend(parse_nessus_file(target, args.protocol))
                else:
                    with open(target, 'r') as target_file:
                        for target_entry in target_file:
                            targets.extend(parse_targets(target_entry))
            else:
                targets.extend(parse_targets(target))


    p_loader = protocol_loader()
    protocol_path = p_loader.get_protocols()[args.protocol]['path']
    protocol_db_path = p_loader.get_protocols()[args.protocol]['dbpath']

    protocol_object = getattr(p_loader.load_protocol(protocol_path), args.protocol)
    protocol_db_object = getattr(p_loader.load_protocol(protocol_db_path), 'database')

    db_path = (cfg.WS_PATH / current_workspace / args.protocol).with_suffix('.db')
    # set the database connection to autocommit w/ isolation level
    db_connection = sqlite3.connect(db_path, check_same_thread=False)
    db_connection.text_factory = str
    db_connection.isolation_level = None
    db = protocol_db_object(db_connection)

    setattr(protocol_object, 'config', cfg.__dict__)

    if hasattr(args, 'module'):

        loader = module_loader(args, db, logger)

        if args.list_modules:
            modules = loader.get_modules()

            for name, props in sorted(modules.items()):
                logger.info('{:<25} {}'.format(name, props['description']))
            sys.exit(0)

        elif args.module and args.show_module_options:

            modules = loader.get_modules()
            for name, props in modules.items():
                if args.module.lower() == name.lower():
                    logger.info('{} module options:\n{}'.format(name, props['options']))
            sys.exit(0)

        elif args.module:
            modules = loader.get_modules()
            for name, props in modules.items():
                if args.module.lower() == name.lower():
                    module = loader.init_module(props['path'])
                    setattr(protocol_object, 'module', module)
                    break

            if not module:
                logger.error('Module not found')
                exit(1)

            if getattr(module, 'opsec_safe') is False:
                ans = raw_input(highlight('[!] Module is not opsec safe, are you sure you want to run this? [Y/n] ', 'red'))
                if ans.lower() not in ['y', 'yes', '']:
                    sys.exit(1)

            if getattr(module, 'multiple_hosts') is False and len(targets) > 1:
                ans = raw_input(highlight("[!] Running this module on multiple hosts doesn't really make any sense, are you sure you want to continue? [Y/n] ", 'red'))
                if ans.lower() not in ['y', 'yes', '']:
                    sys.exit(1)

            if hasattr(module, 'on_request') or hasattr(module, 'has_response'):

                if hasattr(module, 'required_server'):
                    args.server = getattr(module, 'required_server')

                if not args.server_port:
                    args.server_port = 443

                context = Context(db, logger, args)
                module_server = CMXServer(module, context, logger, args.server_host, args.server_port, args.server)
                module_server.start()
                setattr(protocol_object, 'server', module_server.server)

    try:
        '''
            Open all the greenlet threads
        '''

        pool = Pool(args.threads)
        jobs = []
        for target in targets:
            jobs.append(pool.spawn(protocol_object, args, db, str(target)))

        for job in jobs:
            job.join(timeout=args.timeout)

    except (KeyboardInterrupt, gevent.Timeout):
        logging.info("Timed out")
        pass

    if module_server:
        module_server.shutdown()
