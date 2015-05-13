#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: binary -*-

import os
import sys
import json
import getpass # So no one visually snoops on your passphrases.
from optparse import OptionParser

# Add method to truncate wpa.key.table

# The location of the password database.
PASSWORD_DATABASE = os.path.expanduser( '~/.boss.wpa.key.table' )

# Used to identify password database
MAGIC_VALUE = '{}'.format(os.getlogin())
MAGIC_KEY = 'MAGIC_KEY_IDENTIFIER'


class UsageError( Exception ):
    """Catch-all error message"""

    def __init__( self, msg ):
        self.msg = msg
        Exception.__init__(self)

class paint():
    # Console paint
    N = '\033[0m' #  (normal)
    W = '\033[1;37m' # white
    R = '\033[31m' # red
    G = '\033[32m' # green
    O = '\033[33m' # orange
    B = '\033[34m' # blue
    P = '\033[35m' # purple
    C = '\033[36m' # cyan
    T = '\033[93m' # tan
    Y = '\033[1;33m' # yellow
    GR = '\033[37m' # gray
    BR = '\033[2;33m' # brown

class notifications():
    # Colored variables for output use.
    INFO = paint.W+"[INFO]"+paint.N + ": "
    ERROR = paint.R+"[ERROR]"+paint.N + ": "
    FOUND = paint.W+"[FOUND]"+paint.N + ": "

def Help():
    print """
    [GWF CERTIFIED] - https://twitter.com/GuerrillaWF

    Basic Usage: ./boss.py [OPTION]

    ./boss.py list | List all networks that are available in the table.

    ./boss.py get -n [NETWORK-ID] | Retrieve a networks WPA Key.

    ./boss.py create -n [NETWORK-ID] | Store ESSID/BSSID and WPA Key.

    ./boss.py delete -n [NETWORK-ID] | Delete a network and its respective password from the table.
    """

def get_options():
    """Configures the options"""

    opt = OptionParser(add_help_option=False)

    opt.add_option( '-n',
                    dest='network_id',
                    default=None,
                    help='ESSID@BSSID')

    (myopts, myargs) = opt.parse_args()
    return (opt, myopts, myargs)

def output_password(network):
    database = load_database()
    return database[network]['passphrase']

def load_database():
    """Load JSON password database"""

    try:
        myfile = open( PASSWORD_DATABASE, 'r' )
        mydb = json.loads( myfile.read() )

        if( not mydb.has_key(MAGIC_KEY) or
            not mydb[MAGIC_KEY] == MAGIC_VALUE ):
            raise ValueError()

        del mydb[MAGIC_KEY]

        myfile.close()

    except IOError:
        mydb = {}

    except ValueError:
        print( "The file \"%s\" is not a boss.py database."
               % PASSWORD_DATABASE )
        print(
            "Please configure a different "
            + "path for PASSWORD_DATABASE." )
        sys.exit(1)

    return mydb


def save_database(mydb):
    """Save JSON password database"""

    # Set magic key to identify file
    mydb[MAGIC_KEY] = MAGIC_VALUE

    try:
        myfile = open( PASSWORD_DATABASE, 'w' )
        myfile.write( json.dumps(mydb, sort_keys=True, indent=2 ) )
        myfile.close()
    except IOError:
        print "Error: Cannot write database file: %s" % PASSWORD_DATABASE
        sys.exit(1)


def create_network(mydb, opts):
    """Create a new password"""

    if opts.network_id == None:
        raise UsageError( 'Need a user/hostname option for password creation.')

    if mydb.has_key(opts.network_id):
        msg  = '%sPassphrase already stored for %s.\n' % (notifications.ERROR, opts.network_id)
        msg += '%sPlease delete it from the database if you want to replace it:\n' % notifications.INFO
        msg += '%s./boss.py delete -u %s' % (notifications.INFO, opts.network_id)
        raise UsageError( msg )

    print "\nStoring passphrase for %s ...\n" % opts.network_id

    passwd  = getpass.getpass( "Enter Password: " )
    passwd2 = getpass.getpass( "Re-enter: " )

    if not passwd == passwd2:
        print "Passwords do not match. Please try again."
        sys.exit(1)

    mydb[opts.network_id] = {'passphrase':passwd2}

    print "\n{}Passphrase stored for {}\n".format(notifications.INFO, opts.network_id)

def get_password_for_network( mydb, opts):
    """Retrieve a password from database"""

    if not mydb.has_key( opts.network_id ):
        print "{}{} not in table.".format(notifications.ERROR, opts.network_id)
        sys.exit(1)

    passphrase = output_password(opts.network_id)
    print "{}{}: {}".format(notifications.FOUND, opts.network_id ,passphrase)

def list_network( mydb, opts ):
    """List networks in the database"""

    if len(mydb) < 1:
        print "{}No network/passphrases in table.".format(notifications.ERROR)
        exit(0)

    for network in mydb:
        print network

def delete_network( mydb, opts ):
    """Delete a password from the database"""

    if mydb.has_key( opts.network_id ):
        question = "Are you sure you want to delete %s from the database? [y/n]"
        resp = raw_input( question % opts.network_id )

        if resp == 'y':
            del mydb[ opts.network_id ]
        else:
            print "{}Network: {} was not deleted from table.".format(notifications.INFO, opts.network_id)

    else:
        print "{}No password for {} found in database.".format(notifications.ERROR, opts.network_id)
        sys.exit(1)

def main(IFNOARGATALL):
    """The main function"""

    mydb = load_database()

    (parser, opts, args) = get_options()

    actions = { 'create': create_network,
                'get':    get_password_for_network,
                'list':   list_network,
                'delete': delete_network }

    try:
        if len(args) != 1 or not actions.has_key(args[0]):
            Help()
        else:
            action = args[0]
            actions[action](mydb, opts)

    except UsageError as uerr:
        print uerr.msg
        sys.exit(1)

    except KeyboardInterrupt:
        print
        sys.exit(1)

    save_database( mydb )


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except IndexError:
        Help()
