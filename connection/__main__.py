import argparse
import os
from pathlib import Path

from pymongo import MongoClient

from connection.admin import register_admin
from connection.vpn_service import VPNServer


def load_key(path: Path):
    return path.read_text().strip() if path.exists() else None


def save_key(path: Path, private_key: str):
    # Only the owner may read the identity that clients pin.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as file: file.write(private_key)


def serve(options: argparse.Namespace) -> VPNServer:
    key = load_key(options.key)
    mongo = MongoClient(options.mongo)
    server = VPNServer(mongo, options.database, key, public=options.public,
                       internet=options.internet)
    if not key: save_key(options.key, server.private_key)
    server.ip_address, server.panel = options.address, register_admin
    # Every network exposes the panel; one without an address takes its last host.
    for network in server.table_name['networks'].find({}):
        server.add_panel(network['_id'])
    server.load_forwards()
    mode = 'public' if options.public else 'local'
    internet = 'allowed per network' if options.internet else 'disabled'
    print(f'Mode: {mode}', f'Internet: {internet}', f'Public key: {server.public_key}', sep='\n')
    server.run_server(options.port)
    return server


def main(arguments: list[str] = None):
    parser = argparse.ArgumentParser(prog='python -m connection')
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('serve', help='run the VPN server')
    command.add_argument('--mongo', default='mongodb://localhost:27017/')
    command.add_argument('--database', default='vpn_service')
    command.add_argument('--address', default='0.0.0.0')
    command.add_argument('--port', type=int, default=5732)
    command.add_argument('--key', type=Path, default=Path('server.key'),
                         help='private key file; created on the first run')
    command.add_argument('--public', action='store_true',
                         help='open registration: unknown emails create an organization')
    command.add_argument('--internet', action='store_true',
                         help='let networks that allow it reach the internet through this server')
    options = parser.parse_args(arguments)
    if options.command == 'serve': return serve(options)


if __name__ == '__main__': main()
