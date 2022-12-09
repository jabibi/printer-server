# Explicit import to enable 'python app.py'
import argparse
import hashlib
import inspect
import os
import sqlite3
import uuid
from flask import Flask
from flask_cors import CORS, cross_origin
from flask_jsonrpc import JSONRPC
from flask.ext.httpauth import HTTPBasicAuth
from printer import PrinterController

ROOT_DIR = os.path.dirname(os.path.abspath(inspect.getfile(
    inspect.currentframe())))
DB = ROOT_DIR + '/users.db'
PRINTER = PrinterController()

parser = argparse.ArgumentParser(
    description='Provide a JSON-RPC proxy for a Zebra printer.'
)
parser.add_argument('--host', help="host to listen on", default="127.0.0.1")
parser.add_argument('-p', '--port', help='the port to run on', default="8443")
parser.add_argument('-d', '--device', help='name of the printer to print to',
                    default="zebra_python_unittest")
args = parser.parse_args()

app = Flask(__name__)
cors = CORS(app, allow_headers=["Content-type", "Authorization"])
auth = HTTPBasicAuth()
jsonrpc = JSONRPC(app, "/api")


# Not a route on purpose.
# Use an interactive Python shell to add users.
def add_user(username, password):
    '''Adds a new JSON-RPC user to the database.'''

    salt = str(uuid.uuid4())
    db = sqlite3.connect(DB)
    db.cursor().execute('''
        INSERT INTO users(username, pwd_hash, salt) VALUES (?, ?, ?)
    ''', (username, hashlib.sha256(
        password + "\x00" + salt).hexdigest(), salt))
    db.commit()
    db.close()


# Not a route on purpose.
# Use an interactive Python shell to delete users.
def delete_user(username):
    '''Adds a new JSON-RPC user to the database.'''

    db = sqlite3.connect(DB)
    db.cursor().execute("DELETE FROM users WHERE username=?", (username,))
    db.commit()
    db.close()


@auth.verify_password
def verify_pwd(username, password):
    '''Verifies the given username and password.'''

    db = sqlite3.connect(DB)
    cr = db.cursor()
    cr.execute('''
        SELECT pwd_hash, salt FROM users WHERE username = ?
    ''', (username,))
    user = cr.fetchone()
    db.close()

    return bool(user) and (
        user[0] == hashlib.sha256(password + "\x00" + user[1]).hexdigest()
    )


# Routes & JSON-RPC methods ##
@app.route("/")
def index():
    return "SSL exception added for this session."


@jsonrpc.method("output")
@auth.login_required
@cross_origin
def output(printer_name=None, format="epl2", data=[], length=6, width=4,
           raw=False):
    '''Print something on the printer.'''
    if not printer_name:
        printer_name = args.device or "zebra_python_unittest"

    return PRINTER.output(printer_name=printer_name, format=format,
                          data=data, raw=raw,
                          test=False)


def run():
    # Setup database
    db = sqlite3.connect(DB)
    db.cursor().execute('''
        CREATE TABLE IF NOT EXISTS
        users(username TEXT PRIMARY KEY, pwd_hash TEXT, salt TEXT)
    ''')
    db.commit()
    db.close()

    app.run(args.host, debug=False, port=int(args.port))


if __name__ == "__main__":
    run()
