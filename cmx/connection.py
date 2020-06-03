#!/usr/bin/env python3

####################################################################
#   connection.py   -   Connects to target and executes actions based on passed in arguments
#   
# This class defines and executes the cmx connection flow:
#     1  setup up protocol logger
#     2  creates the connection object
#     3  performs initial connection enum
#     4  displays connection info
#     5  attempts login
#     6  if module, runs module
#     7  if action, performs action
#
#
# Class:
#   connection
#
# Class Functions:
#   proto_args(std_parser, module_parser)
#   proto_logger()
#   enum_host_info()
#   print_host_info(info)
#   create_conn_obj()
#   check_if_admin()
#   plaintext_login(domain, username, password)
#   hash_login(domain, username, ntlm_hash)
#   proto_flow()
#
####################################################################

import logging
from io import IOBase
from gevent.lock import BoundedSemaphore
from gevent.socket import gethostbyname
from functools import wraps
from cmx.logger import CMXLogAdapter
from cmx.context import Context

sem = BoundedSemaphore(1)
global_failed_logins = 0
user_failed_logins = {}

def requires_admin(func):
    def _decorator(self, *args, **kwargs):
        if self.admin_privs is False: 
            print('\n          Unable to execute, user must have local admin privileges\n') # ... logger would be better...
            return
        return func(self, *args, **kwargs)
    return wraps(func)(_decorator)

def requires_dc(func):
    def _decorator(self, *args, **kwargs):
        if self.dc_ip == '': 
            print('\n          Unable to execute, must specify a domain controller (-dc)\n') # ... logger would be better...
            return
        return func(self, *args, **kwargs)
    return wraps(func)(_decorator)
    
class connection(object):
    """ Base connection object """ 

    def __init__(self, args, db, host):
        self.args = args
        self.db = db
        self.hostname = host
        self.conn = None
        self.admin_privs = False
        self.logger = None
        self.password = None
        self.username = None
        self.failed_logins = 0
        self.local_ip = None

        try:
            self.host = gethostbyname(self.hostname)
        except Exception as e:
            logging.debug('Error resolving hostname {}: {}'.format(self.hostname, e))
            return

        self.proto_flow()

    @staticmethod
    def proto_args(std_parser, module_parser):
        return

    def proto_logger(self):
        pass

    def enum_host_info(self):
        return

    def print_host_info(self, info):
        return

    def create_conn_obj(self):
        return

    def check_if_admin(self):
        return

    def plaintext_login(self, domain, username, password):
        return

    def hash_login(self, domain, username, ntlm_hash):
        return


    def proto_flow(self):
        """ Program flow of cmx """ 
        self.proto_logger()
        if self.create_conn_obj():    # calls the create_conn_object method of the protocol class we are in     
            self.enum_host_info()
            self.print_host_info()
            self.login()
            if hasattr(self.args, 'module') and self.args.module:
                self.call_modules()
            else:
                self.call_cmd_args()


    def call_cmd_args(self):
        for k, v in list(vars(self.args).items()):
            if hasattr(self, k) and hasattr(getattr(self, k), '__call__'):
                if v is not False and v is not None:
                    logging.debug('Calling {}()'.format(k))
                    getattr(self, k)()

    def call_modules(self):
        module_logger = CMXLogAdapter(extra={
                                          'module': self.module.name.upper(),
                                          'host': self.host,
                                          'port': self.args.port,
                                          'hostname': self.hostname
                                         })

        context = Context(self.db, module_logger, self.args)
        context.localip  = self.local_ip

        if hasattr(self.module, 'on_request') or hasattr(self.module, 'has_response'):
            self.server.connection = self
            self.server.context.localip = self.local_ip

        if hasattr(self.module, 'on_login'):
            self.module.on_login(context, self)

        if self.admin_privs and hasattr(self.module, 'on_admin_login'):
            self.module.on_admin_login(context, self) #self is our protocolconnection obj here
        elif hasattr(self.module, 'on_admin_login') and not self.admin_privs:
            print('')
            module_logger.announce('Unable to execute module, user must have local admin privileges')
            print('')

        if (not hasattr(self.module, 'on_request') and not hasattr(self.module, 'has_response')) and hasattr(self.module, 'on_shutdown'):
            self.module.on_shutdown(context, self)

    def inc_failed_login(self, username):
        global global_failed_logins
        global user_failed_logins

        if username not in list(user_failed_logins.keys()):
            user_failed_logins[username] = 0

        user_failed_logins[username] += 1
        global_failed_logins += 1
        self.failed_logins += 1

    def over_fail_limit(self, username):
        global global_failed_logins
        global user_failed_logins

        if global_failed_logins == self.args.gfail_limit: return True

        if self.failed_logins == self.args.hfail_limit: return True

        if username in list(user_failed_logins.keys()):
            if self.args.ufail_limit == user_failed_logins[username]: return True

        return False

    def login(self):
        for cred_id in self.args.cred_id:
            with sem:
                if cred_id.lower() == 'all':
                    creds = self.db.get_credentials()
                else:
                    creds = self.db.get_credentials(filterTerm=int(cred_id))

                for cred in creds:
                    logging.debug(cred)
                    try:
                        c_id, domain, username, password, credtype, pillaged_from = cred

                        if credtype and password:

                            if not domain: domain = self.domain

                            if self.args.local_auth:
                                domain = self.domain
                            elif self.args.domain:
                                domain = self.args.domain

                            if credtype == 'hash' and not self.over_fail_limit(username):
                                if self.hash_login(domain, username, password): return True

                            elif credtype == 'plaintext' and not self.over_fail_limit(username):
                                if self.plaintext_login(domain, username, password): return True

                    except IndexError:
                        self.logger.error("Invalid database credential ID!")


        if self.args.hash:
            for user in self.args.username:
                if isinstance(user, IOBase): #list of users
                    for usr in user:
                        with sem:
                            for ntlm_hash in self.args.hash:
                                if not isinstance(ntlm_hash, IOBase): # Not a list of hashes
                                    if not self.over_fail_limit(usr.strip()):
                                        if self.hash_login(self.domain, usr.strip(), ntlm_hash): return True

                                elif isinstance(ntlm_hash, IOBase):
                                    for f_hash in ntlm_hash:
                                        if not self.over_fail_limit(usr.strip()):
                                            if self.hash_login(self.domain, usr.strip(), f_hash.strip()): return True
                                    ntlm_hash.seek(0)

                elif not isinstance(user, IOBase): #not a list of users
                        with sem:
                            for ntlm_hash in self.args.hash:
                                if not isinstance(ntlm_hash, IOBase): # Not a list of hashes
                                    if not self.over_fail_limit(user):
                                        if self.hash_login(self.domain, user, ntlm_hash): return True

                                elif isinstance(ntlm_hash, IOBase):
                                    for f_hash in ntlm_hash:
                                        if not self.over_fail_limit(user):
                                            if self.hash_login(self.domain, user, f_hash.strip()): return True
                                    ntlm_hash.seek(0)


        elif self.args.password and isinstance(self.args.password[0], IOBase) and isinstance(self.args.username[0], IOBase):
        # If we get a list of usernames AND passwords
        # we want to loop through each user and try the password
            for password in self.args.password:
                for f_pass in password:
                    with sem:
                        for user in self.args.username:
                            for usr in user:
                                if not self.over_fail_limit(usr.strip()):
                                    if self.plaintext_login(self.domain, usr.strip(), f_pass.strip()): return True
                            user.seek(0)

        else:
            # not a list of users AND (passwords or hashes)
            for user in self.args.username:
                if isinstance(user, IOBase): #list of users
                    for usr in user:
                        with sem:
                            for password in self.args.password:
                                if not isinstance(password, IOBase): # Not a list of passwds
                                    if not self.over_fail_limit(usr.strip()):
                                        if self.plaintext_login(self.domain, usr.strip(), password): return True

                                elif isinstance(password, IOBase):
                                    for f_pass in password:
                                        if not self.over_fail_limit(usr.strip()):
                                            if self.plaintext_login(self.domain, usr.strip(), f_pass.strip()): return True
                                    password.seek(0)

                elif not isinstance(user, IOBase): #not a list of users
                    with sem:
                        for password in self.args.password:
                            if not isinstance(password, IOBase):  # Not a list of passwds
                                if not self.over_fail_limit(user):
                                    if hasattr(self.args, 'domain'):
                                        if self.plaintext_login(self.domain, user, password): return True
                                    else:
                                        if self.plaintext_login(user, password): return True

                            elif isinstance(password, IOBase): # Not a list of passwds
                                for f_pass in password:
                                    if not self.over_fail_limit(user):
                                        if hasattr(self.args, 'domain'):
                                            if self.plaintext_login(self.domain, user, f_pass.strip()): return True
                                        else:
                                            if self.plaintext_login(user, f_pass.strip()): return True
                                password.seek(0)
