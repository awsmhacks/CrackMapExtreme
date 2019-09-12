

import sqlite3

import pandas as pd
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter

from colorama import init
from termcolor import colored

from cmx import config as cfg


init()

my_completer = WordCompleter(['back', 'help', 'smb', 'list', 'creds',
                              'hosts', 'exit'], ignore_case=True)


genHelp = """Available Commands:
    help - Show Help Menu
    smb - Enter the SMB Database
    exit - Exits CMXDB
    """

smbHelp = """Available Commands:
    back - Go back one level
    help - Show Help for this protocol
    help <command> - Show Help for command
    list - show available tables
    creds - List Credentials Stored in Database
    hosts - List Hosts Stored in Database
    add host - Add a host to the database
    add cred - Add a credential to the database
"""

addHostHelp = """Adding a Host to the DB:
    All values are required
add host <ip> <hostname> <domain> <os> <dc>
"""

addCredHelp = """Adding a Cred to the DB:
    All values are required
add cred <domain> <username> <password> <credtype> <HostID-creds-obtained-from>
"""


class CMXDB():

    def __init__(self):
        self.connection = None
        self.proto = ''
        self.workspace = cfg.WORKSPACE
        self.prompt_str = 'cmxdb {} {}> '.format(self.workspace, self.proto)
        self.proto_db_path = None
        self.session = PromptSession(completer=my_completer)
        self.working = True

    def run(self):
        while self.working:
            try:
                text = self.session.prompt(self.prompt_str)
            except KeyboardInterrupt:
                continue    # Control-C pressed. Try again.
            except EOFError:
                break       # Control-D pressed.

            self.do_work(text.strip().lower())

    def connect_db(self, protocol=''):

        proto_db_path = (cfg.WS_PATH / cfg.WORKSPACE / protocol).with_suffix('.db')

        if proto_db_path.is_file():
            self.connection = sqlite3.connect(proto_db_path)
            self.proto = protocol
            return
        else:
            print('No database found for {}'.format(protocol))
        return

    def show_help(self, command):
        global genHelp
        global smbHelp
        global addHostHelp
        global addCredHelp

        if command == 'help' and self.proto == '':
            print(genHelp)
        elif command == 'help' and self.proto == 'smb':
            print(smbHelp)
        elif command.startswith('help add cred'):
            print(addCredHelp)
        elif command.startswith('help add host'):
            print(addHostHelp)
        elif command.startswith('help smb'):
            print(smbHelp)
        else:
            print("There's no help for you")

    def list_tables(self):

        if self.connection:
            with self.connection:
                try:
                    messages = self.connection.execute(
                        "SELECT name FROM sqlite_master WHERE type ='table' "
                        "AND name NOT LIKE 'sqlite_%';")
                except Exception as e:
                    print(repr(e))
                else:
                    for message in messages:
                        print(message)
        else:
            print('Not connected to a database yet')

    def do_back(self):

        if self.connection:
            self.proto = ''
            self.connection = None
        else:
            print('Nowhere to back out of')

    def show_creds(self, filterTerm=None, credType=None):

        pd.set_option('display.max_colwidth', 68)
        if self.connection:
            with self.connection:
                try:
                        # if we're returning a single credential by ID
                    if self.is_credential_valid(filterTerm):
                        print(colored(pd.read_sql_query(
                            "SELECT * FROM users WHERE id=?", [filterTerm])))

                    elif credType:
                        print(colored(pd.read_sql_query(
                            "SELECT * FROM users WHERE credtype=?", [credType])))

                    # if we're filtering by username
                    elif filterTerm and filterTerm != '':
                        print(colored(pd.read_sql_query(
                            "SELECT * FROM users WHERE LOWER(username) "
                            "LIKE LOWER(?)", ['%{}%'.format(filterTerm)])))

                    # otherwise return all credentials
                    else:
                        print(colored(pd.read_sql_query(
                            "SELECT id, domain, username, password FROM users WHERE password IS NOT NULL",
                            self.connection, index_col='id'), "green"))
                except Exception as e:
                    print(repr(e))
                else:
                    # for result in results:
                    print('')
        else:
            print('Not connected to a database yet')

    def show_creds(self, filterTerm=None, credType=None):

        pd.set_option('display.max_colwidth', 68)
        if self.connection:
            with self.connection:
                try:
                        # if we're returning a single credential by ID
                    if self.is_credential_valid(filterTerm):
                        print(colored(pd.read_sql_query(
                            "SELECT * FROM users WHERE id=?", [filterTerm])))

                    elif credType:
                        print(colored(pd.read_sql_query(
                            "SELECT * FROM users WHERE credtype=?", [credType])))

                    # if we're filtering by username
                    elif filterTerm and filterTerm != '':
                        print(colored(pd.read_sql_query(
                            "SELECT * FROM users WHERE LOWER(username) "
                            "LIKE LOWER(?)", ['%{}%'.format(filterTerm)])))

                    # otherwise return all credentials
                    else:
                        print(colored(pd.read_sql_query(
                            "SELECT id, domain, username, password FROM users",
                            self.connection, index_col='id'), "green"))
                except Exception as e:
                    print(repr(e))
                else:
                    # for result in results:
                    print('')
        else:
            print('Not connected to a database yet')

    def show_hosts(self, filterTerm=None, credType=None):

        pd.set_option('display.max_colwidth', 68)
        if self.connection:
            with self.connection:
                try:
                        # if we're returning a single credential by ID
                    if self.is_credential_valid(filterTerm):
                        print(colored(pd.read_sql_query(
                            "SELECT * FROM computers WHERE id=? LIMIT 1", [filterTerm])))

                    elif credType:
                        print(colored(pd.read_sql_query(
                            "SELECT * FROM computers WHERE credtype=?", [credType])))

                    # if we're filtering by username
                    elif filterTerm and filterTerm != '':
                        print(colored(pd.read_sql_query(
                            "SELECT * FROM computers WHERE LOWER(hostname) "
                            "LIKE LOWER(?)", ['%{}%'.format(filterTerm)])))

                    # otherwise return all credentials
                    else:
                        print(colored(pd.read_sql_query(
                            "SELECT * FROM computers",
                            self.connection, index_col='id'), "green"))
                except Exception as e:
                    print(repr(e))
                else:
                    # for result in results:
                    print('')
        else:
            print('Not connected to a database yet')


    def is_credential_valid(self, credentialID):
        """
        Check if this credential ID is valid.
        """

        if self.connection:
            with self.connection:
                try:
                    results = self.connection.execute(
                        "SELECT * FROM users WHERE id=? AND password IS NOT "
                        "NULL LIMIT 1", [credentialID])
                except Exception as e:
                    print(repr(e))
                    return False
                else:
                    result = results.fetchall()
                    return len(result) > 0
        else:
            print('Not connected to a database yet')
            return False

    def do_work(self, command=''):

        if command == '':
            return

        if command.startswith('help ') or command == 'help':
            self.show_help(command)
            return

        if command == 'smb':
            self.connect_db('smb')
            return

        if command == 'list':
            self.list_tables()
            return

        if command == 'back':
            self.do_back()
            return

        if command == 'exit':
            self.working = False
            return

        if command == 'creds':
            self.show_creds()
            return

        if command == 'hosts':
            self.show_hosts()
            return

        else:
            print("Unknown Command")
            return


def main():

    dbnav = CMXDB()
    dbnav.run()
    print('GoodBye!')
