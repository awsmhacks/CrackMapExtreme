#!/usr/bin/env python3

####################################################################
#   cmxdb.py   -   CMXDB entry point
#   
#   Executes the REPL for the CMX DB
#   
#    
#   
#
#
# Classes:
#   DatabaseNavigator
#   CMXDBMenu
#
# Non-Class Functions:
#   main
#
####################################################################

import cmd
import sqlite3
import sys
import os
from time import sleep
import asciitable
from configparser import ConfigParser
from cmx.loaders.protocol_loader import protocol_loader
from cmx import config as cfg
from pathlib import Path

class UserExitedProto(Exception):
    pass


class DatabaseNavigator(cmd.Cmd):

    def __init__(self, main_menu, database, proto):
        cmd.Cmd.__init__(self)

        self.main_menu = main_menu
        self.proto = proto
        self.db = database
        self.prompt = 'cmxdb ({})({}) > '.format(main_menu.workspace, proto)

    def do_back(self, line):
        raise UserExitedProto

    def do_exit(self, line):
        sys.exit(0)

    def print_table(self, data, title=None):
        print("")
        table = asciitable.read(data)
        if title:
            table.title = title
        print(table.table)
        print("")

    def do_export(self, line):
        if not line:
            print("[-] not enough arguments")
            return

        line = line.split()

        if line[0].lower() == 'creds':
            if len(line) < 3:
                print("[-] invalid arguments, export creds <plaintext|hashes|both|csv> <filename>")
                return
            if line[1].lower() == 'plaintext':
                creds = self.db.get_credentials(credtype="plaintext")
            elif line[1].lower() == 'hashes':
                creds = self.db.get_credentials(credtype="hash")
            else:
                creds = self.db.get_credentials()

            with open(os.path.expanduser(line[2]), 'w') as export_file:
                for cred in creds:
                    credid, domain, user, password, credtype, fromhost = cred
                    if line[1].lower() == 'csv':
                        export_file.write('{},{},{},{},{},{}\n'.format(credid,domain,user,password,credtype,fromhost))
                    else:
                        export_file.write('{}\n'.format(password))
            print('[+] creds exported')

        elif line[0].lower() == 'hosts':
            if len(line) < 2:
                print("[-] invalid arguments, export hosts <filename>")
                return
            hosts = self.db.get_computers()
            with open(os.path.expanduser(line[1]), 'w') as export_file:
                for host in hosts:
                    hostid,ipaddress,hostname,domain,opsys,dc = host
                    export_file.write('{},{},{},{},{},{}\n'.format(hostid,ipaddress,hostname,domain,opsys,dc))
            print('[+] hosts exported')

        else:
            print('[-] invalid argument, specify creds or hosts')


    def do_import(self, line):
        return

    def complete_import(self, text, line, begidx, endidx):
        "Tab-complete 'import' commands."

        commands = ["empire", "metasploit"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]

    def complete_export(self, text, line, begidx, endidx):
        "Tab-complete 'creds' commands."

        commands = ["creds", "plaintext", "hashes"]

        mline = line.partition(' ')[2]
        offs = len(mline) - len(text)
        return [s[offs:] for s in commands if s.startswith(mline)]


class CMXDBMenu(cmd.Cmd):

    def __init__(self):
        cmd.Cmd.__init__(self)

        self.workspace_dir = cfg.WS_PATH
        self.conn = None
        self.p_loader = protocol_loader()
        self.protocols = self.p_loader.get_protocols()

        self.workspace = cfg.WORKSPACE
        self.do_workspace(cfg.WORKSPACE)

        self.db = cfg.last_used_db
        if self.db:
            self.do_proto(self.db)

    def open_proto_db(self, db_path):
        # Set the database connection to autocommit w/ isolation level
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.text_factory = str
        self.conn.isolation_level = None


    def do_proto(self, proto):
        if not proto:
            return

        proto_db_path = (cfg.WS_PATH / cfg.WORKSPACE / proto).with_suffix('.db')
        if os.path.exists(proto_db_path):
            self.open_proto_db(proto_db_path)
            db_nav_object = self.p_loader.load_protocol(self.protocols[proto]['nvpath'])
            db_object = self.p_loader.load_protocol(self.protocols[proto]['dbpath'])
            cfg.last_used_db = proto

            try:
                proto_menu = getattr(db_nav_object, 'navigator')(self, getattr(db_object, 'database')(self.conn), proto)
                proto_menu.cmdloop()
            except UserExitedProto:
                pass

    def do_workspace(self, line):
        if not line:
            return

        line = line.strip()

        if line.split()[0] == 'create':
            new_workspace = line.split()[1].strip()

            print("[*] Creating workspace '{}'".format(new_workspace))
            os.mkdir((self.workspace_dir / new_workspace))

            for protocol in list(self.protocols.keys()):
                try:
                    protocol_object = self.p_loader.load_protocol(self.protocols[protocol]['dbpath'])
                except KeyError:
                    continue

                proto_db_path = (self.workspace_dir / new_workspace / protocol).with_suffix('.db')

                if not os.path.exists(proto_db_path):
                    print('[*] Initializing {} protocol database'.format(protocol.upper()))
                    conn = sqlite3.connect(proto_db_path)
                    c = conn.cursor()

                    # try to prevent some of the weird sqlite I/O errors
                    c.execute('PRAGMA journal_mode = OFF')
                    c.execute('PRAGMA foreign_keys = 1')

                    getattr(protocol_object, 'database').db_schema(c)

                    # commit the changes and close everything off
                    conn.commit()
                    conn.close()

            self.do_workspace(new_workspace)

        elif (self.workspace_dir / line).is_dir():
            cfg.WORKSPACE = line
            self.workspace = line
            self.prompt = 'cmxdb ({}) > '.format(line)

    def do_exit(self, line):
        sys.exit(0)


def main():

    try:
        cmxdbnav = CMXDBMenu()
        cmxdbnav.cmdloop()
    except KeyboardInterrupt:
        pass
