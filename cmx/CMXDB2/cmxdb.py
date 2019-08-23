
import sys
import sqlite3

import pandas as pd
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter

from colorama import init 
from termcolor import colored

from cmx import config as cfg


init()

my_completer = WordCompleter([
    'back', 'help', 'smb', 'list', 'creds', 'hosts',
    'exit'], ignore_case=True)

genHelp = """Available Commands:
    help - Show Help Menu
    smb - Enter the SMB Database
    exit - Exits CMXDB
    """

protoHelp = """Available Commands:
    back - Go back one level
    help <command> - Show Help for command
    smb - Enter the SMB Database
    list - show available tables
    creds - List Credentials Stored in Database
    hosts - List Hosts Stored in Database
    add host - Add a host to the database
    add cred - Add a credential to the database
"""

addHostHelp = """Adding a Host to the DB:
add host - Add a host to the database, all vals required
    add host <ip> <hostname> <domain> <os> <dc>  
"""

addCredHelp = """Adding a Cred to the DB:
All values are required
    add cred <domain> <username> <password> <credtype> <HostID-creds-obtained-from> 
"""


connection = None
prompt_str = '> '
working = True


def connect_db(protocol=''):
    global prompt_str

    workspace_dir = cfg.WS_PATH
    workspace = cfg.WORKSPACE
    conn = None
    proto_db_path = (cfg.WS_PATH / cfg.WORKSPACE / protocol).with_suffix('.db')

    
    if proto_db_path.is_file():
        conn = sqlite3.connect(proto_db_path)
        prompt_str += protocol + '> '
    else:
        print ('No database found for {}'.format(protocol))
    return conn



def show_help(command):
    global genHelp
    global protoHelp
    global addHostHelp
    global addCredHelp

    if command == 'help': print(genHelp)
    elif command.startswith('help add cred'): print(addCredHelp)
    elif command.startswith('help add host'): print(addHostHelp)
    elif command.startswith('help smb'): print(protoHelp)
    else: print("There's no help for you") 


def list_tables():
    global connection
    if connection:
        with connection:
            try:
                messages = connection.execute("SELECT name FROM sqlite_master WHERE type ='table' AND name NOT LIKE 'sqlite_%';")
            except Exception as e:
                print(repr(e))
            else:
                for message in messages:
                    print(message)
    else:
        print('Not connected to a database yet')


def show_creds(filterTerm=None, credType=None):
    global connection
    pd.set_option('display.max_colwidth', 68)
    if connection:
            with connection:
                try:
                    # if we're returning a single credential by ID
                    if is_credential_valid(filterTerm):
                        results = connection.execute("SELECT * FROM users WHERE id=?", [filterTerm])
                
                    elif credType:
                        results = connection.execute("SELECT * FROM users WHERE credtype=?", [credType])
                
                    # if we're filtering by username
                    elif filterTerm and filterTerm != '':
                        results = connection.execute("SELECT * FROM users WHERE LOWER(username) LIKE LOWER(?)", ['%{}%'.format(filterTerm)])
                
                    # otherwise return all credentials
                    else:
                        print (colored(pd.read_sql_query("SELECT id, domain, username, password FROM users", connection, index_col='id'), "green"))
                except Exception as e:
                    print(repr(e))
                else:
                    #for result in results:
                    print('')
    else:
        print('Not connected to a database yet')


def is_credential_valid(credentialID):
    """
    Check if this credential ID is valid.
    """
    global connection
    if connection:
        with connection:
            try:
                results = connection.execute('SELECT * FROM users WHERE id=? AND password IS NOT NULL LIMIT 1', [credentialID])
            except Exception as e:
                print(repr(e))
                return False
            else:
                result = results.fetchall()
                return len(result) > 0
    else:
        print('Not connected to a database yet')
        return False



def do_work(command=''):
    global connection
    global working

    if command == '':
        return

    if command.startswith('help ') or command == 'help':
        show_help(command)
        return

    if command == 'smb':
        connection = connect_db('smb')
        return

    if command == 'list':
        list_tables()
        return

    if command == 'back':
        working = False
        return

    if command == 'exit':
        working = False
        return

    if command == 'creds':
        show_creds()
        return

    else:
        print("Unknown Command")
        return




def main():
    session = PromptSession(completer=my_completer)


    while working:
        try:
            text = session.prompt(prompt_str)
        except KeyboardInterrupt:
            continue    # Control-C pressed. Try again.
        except EOFError:
            break       # Control-D pressed.
        
        do_work(text.strip().lower())


    print('GoodBye!')
