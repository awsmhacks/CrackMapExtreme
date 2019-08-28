#!/usr/bin/env python3

import imp
from cmx import config as cfg


class protocol_loader:

    def __init__(self):
        self.cmx_path = cfg.CMX_HOME

    def load_protocol(self, protocol_path):
        protocol = imp.load_source('protocol', str(protocol_path))
        return protocol

    def get_protocols(self):
        protocols = {}
        protocol_paths = [cfg.CMX_PROTO_DIR, (cfg.CMX_HOME / 'protocols')]

        for path in protocol_paths:
            for protocol in path.iterdir():
                if protocol.is_dir() and not protocol.name == '__pycache__':
                    protocol_path = protocol
                    protocol_name = protocol.stem
    
                    db_file_path = protocol / 'database.py'
                    db_nav_path = protocol / 'db_navigator.py'
                    if db_file_path.is_file():
                        protocols[protocol_name]['dbpath'] = db_file_path
                    if db_nav_path.is_file():
                        protocols[protocol_name]['nvpath'] = db_nav_path

        return protocols
