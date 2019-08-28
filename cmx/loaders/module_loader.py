#!/usr/bin/env python3

import imp
from cmx.context import Context
from cmx.logger import CMXLogAdapter
from cmx import config as cfg

class module_loader:

    def __init__(self, args, db, logger):
        self.args = args
        self.db = db
        self.logger = logger
        self.cmx_path = cfg.CMX_HOME

    def module_is_sane(self, module, module_path):
        module_error = False

        if not hasattr(module, 'name'):
            self.logger.error('{} missing the name variable'.format(module_path))
            module_error = True

        elif not hasattr(module, 'description'):
            self.logger.error('{} missing the description variable'.format(module_path))
            module_error = True

        elif not hasattr(module, 'supported_protocols'):
            self.logger.error('{} missing the supported_protocols variable'.format(module_path))
            module_error = True

        elif not hasattr(module, 'opsec_safe'):
            self.logger.error('{} missing the opsec_safe variable'.format(module_path))
            module_error = True

        elif not hasattr(module, 'multiple_hosts'):
            self.logger.error('{} missing the multiple_hosts variable'.format(module_path))
            module_error = True

        elif not hasattr(module, 'options'):
            self.logger.error('{} missing the options function'.format(module_path))
            module_error = True

        elif not hasattr(module, 'on_login') and not (module, 'on_admin_login'):
            self.logger.error('{} missing the on_login/on_admin_login function(s)'.format(module_path))
            module_error = True

        if module_error: return False

        return True

    def load_module(self, module_path):
        try:
            module = imp.load_source('payload_module', str(module_path)).CMXModule()
            if self.module_is_sane(module, str(module_path)):
                return module
        except Exception as e:
            self.logger.error('Failed loading module at {}: {}'.format(module_path, e))

        return None

    def get_modules(self):
        modules = {}

        modules_paths = [cfg.CMX_MOD_DIR, (cfg.CMX_HOME / 'modules')]

        for path in modules_paths:
            for module in path.iterdir():
                if module.name != 'example_module.py' and module.name != '__pycache__':
                    m = self.load_module(module)
                    if m and (self.args.protocol in m.supported_protocols):
                        modules[m.name] = {'path': module, 'description': m.description, 'options': m.options.__doc__}

        return modules

    def init_module(self, module_path):

        module  = None

        module = self.load_module(module_path)

        if module:
            module_logger = CMXLogAdapter(extra={'module': module.name.upper()})
            context = Context(self.db, module_logger, self.args)

            module_options = {}

            for option in self.args.module_options:
                key, value = option.split('=', 1)
                module_options[str(key).upper()] = value

            module.options(context, module_options)

        return module
