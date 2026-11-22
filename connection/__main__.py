import argparse
import os
import signal
import sys
import traceback
from getpass import getpass
from pathlib import Path

from pymongo import MongoClient

from connection import client_cli, console, srp
from connection import workers as sharding
from connection.admin import register_admin
from connection.database.mongodb import Account
from connection.vpn_service import EMAIL, USERNAME, VPNServer, exactly


def load_key(path: Path):
    return path.read_text().strip() if path.exists() else None


def save_key(path: Path, secret: str):
    # Only the owner may read it: it keeps unknown names indistinguishable.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as file: file.write(secret)


def serve(options: argparse.Namespace) -> VPNServer:
    key = load_key(options.key)
    workers = getattr(options, 'workers', None) or (os.cpu_count() or 1 if sharding.available() else 1)
    if workers > 1 and not sharding.available(): raise SystemExit('Several workers need Linux')
    if workers > 255: raise SystemExit('At most 255 workers')
    mode = 'public' if options.public else 'local'
    internet = 'allowed per network' if options.internet else 'disabled'
    if workers == 1:
        mongo = MongoClient(options.mongo)
        server = VPNServer(mongo, options.database, key, public=options.public,
                           internet=options.internet)
        if not key: save_key(options.key, server.secret)
        server.ip_address, server.panel = options.address, register_admin
        # Every network exposes the panel; one without an address takes its last host.
        for network in server.table_name['networks'].find({}):
            server.add_panel(network['_id'])
        server.load_forwards()
        print(f'Mode: {mode}', f'Internet: {internet}', sep='\n')
        server.run_server(options.port)
        return server
    # Several workers: one process per core, each with whole organizations and its own socket.
    if not key:
        key = os.urandom(32).hex()
        save_key(options.key, key)
    sockets = sharding.group(options.address, options.port, workers)
    mailboxes, root = sharding.Mailboxes(workers), os.getpid()
    print(f'Mode: {mode}', f'Internet: {internet}', f'Workers: {workers}', sep='\n', flush=True)
    children = []
    for worker in range(workers):
        pid = os.fork()
        if pid == 0:
            code = 1
            try:
                sharding.orphan_signal()
                for index, udp in enumerate(sockets):
                    if index != worker: udp.close()
                run_worker(options, key, worker, workers, sockets[worker], mailboxes, root)
            except KeyboardInterrupt: code = 0
            except BaseException: traceback.print_exc()
            finally: os._exit(code)
        children.append(pid)
    for udp in sockets: udp.close()
    # Stopping the parent stops the workers too.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    # One worker stopping leaves its organizations unserved: the whole server stops.
    pid = None
    try: pid = os.wait()[0]
    except KeyboardInterrupt: pass
    finally:
        for child in children:
            try: os.kill(child, signal.SIGTERM)
            except ProcessLookupError: pass
        for child in children:
            try: os.waitpid(child, 0)
            except ChildProcessError: pass
    if pid: raise SystemExit(f'Worker {children.index(pid)} stopped, so the server stopped')


def run_worker(options: argparse.Namespace, key: str, worker: int, workers: int,
               udp, mailboxes, root: int):
    # After the fork: its own database connection, then only the organizations it owns.
    mongo = MongoClient(options.mongo)
    server = VPNServer(mongo, options.database, key, public=options.public, internet=options.internet,
                       worker=worker, workers=workers, mailboxes=mailboxes)
    server.ip_address, server.panel, server.metrics_root = options.address, register_admin, root
    server.load_forwards()
    server.run_server(options.port, udp)


def add_account(options: argparse.Namespace, ask=getpass) -> str:
    # For servers without open registration: the operator creates the account.
    if not USERNAME.fullmatch(options.username):
        raise SystemExit('The username needs 3 to 32 letters, digits, dots, dashes or underscores')
    if not EMAIL.fullmatch(options.email): raise SystemExit('The email is not valid')
    accounts = MongoClient(options.mongo)[options.database]['accounts']
    if accounts.find_one(dict(username=exactly(options.username))): raise SystemExit('The username is taken')
    if accounts.find_one(dict(email=exactly(options.email))): raise SystemExit('The email is taken')
    password = ask('Password: ')
    if not password or password != ask('Repeat the password: '): raise SystemExit('The passwords do not match')
    account = Account(accounts).create(username=options.username, email=options.email,
                                       srp=srp.verifier(password), networks={})
    print(f'Created the account {options.username}')
    return account['id']


def window() -> int:
    # No arguments: the desktop window, from the same executable as the commands.
    console.hide_own_console()
    if console.elevate([]): return 0
    from connection.desktop.window import main as desktop
    return desktop(sys.argv[:1])


def main(arguments: list[str] = None):
    arguments = sys.argv[1:] if arguments is None else arguments
    if not arguments: return window()
    parser = argparse.ArgumentParser(prog='python -m connection',
                                     description='Without arguments it opens the desktop window.')
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('serve', help='run the VPN server')
    command.add_argument('--mongo', default='mongodb://localhost:27017/')
    command.add_argument('--database', default='vpn_service')
    command.add_argument('--address', default='0.0.0.0')
    command.add_argument('--port', type=int, default=5732)
    command.add_argument('--key', type=Path, default=Path('server.key'),
                         help='secret file; created on the first run and never shared')
    command.add_argument('--public', action='store_true',
                         help='open registration: anyone creates an account from the client')
    command.add_argument('--internet', action='store_true',
                         help='let networks that allow it reach the internet through this server')
    command.add_argument('--workers', type=int, default=None,
                         help='processes that share the organizations (Linux; default: one per core)')
    command = commands.add_parser('account', help='create an account on this server')
    command.add_argument('username')
    command.add_argument('email')
    command.add_argument('--mongo', default='mongodb://localhost:27017/')
    command.add_argument('--database', default='vpn_service')
    # The client: the same calls code and a visual interface use.
    client_cli.add_commands(commands)
    options = parser.parse_args(arguments)
    if options.command == 'serve': return serve(options)
    if options.command == 'account': return add_account(options)
    return client_cli.run(options)


if __name__ == '__main__':
    # Client commands end with their exit code; the server runs until stopped.
    result = main()
    if type(result) is int: raise SystemExit(result)
