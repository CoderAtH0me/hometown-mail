#!/usr/bin/env python3
# Part of Odoo. See LICENSE file for full copyright and licensing details.
#
# odoo-mailgate
#
# This program will read an email from stdin and forward it to odoo.
# Configure a pipe alias in your mail server to use it, for example in postfix:
#
# email@address: "|/path/to/odoo-mail.py"
#
# or in exim:
#
# *: |/path/to/odoo-mail.py
#
import argparse
import sys
import traceback
import xmlrpc.client

def main():
    parser = argparse.ArgumentParser(usage='%(prog)s [options]', description='Odoo Mailgate Script')
    parser.add_argument("-d", "--database", help="Odoo database name", default='first_db')
    parser.add_argument("-u", "--userid", help="Odoo user id to connect with", type=int, default=3)
    parser.add_argument("-p", "--password", help="Odoo user password", default='supersecret')
    parser.add_argument("--host", help="Odoo host", default='192.168.43.215')
    parser.add_argument("--port", help="Odoo port", type=int, default=8069)
    args = parser.parse_args()

    try:
        msg = sys.stdin.read()
        models = xmlrpc.client.ServerProxy('http://{}:{}/xmlrpc/2/object'.format(args.host, args.port), allow_none=True)
        models.execute_kw(args.database, args.userid, args.password, 'portal.email.thread', 'message_process', [False, xmlrpc.client.Binary(msg.encode())], {})
    except xmlrpc.client.Fault as e:
        # reformat xmlrpc faults to print a readable traceback
        err = "xmlrpc.client.Fault: {}\n{}".format(e.faultCode, e.faultString)
        sys.exit(err)
    except Exception as e:
        traceback.print_exc()
        sys.exit(2)

if __name__ == '__main__':
    main()
