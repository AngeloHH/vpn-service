import argparse
import ctypes
import json
import os
import threading
from getpass import getpass

from connection import VPNClient, VPNServer


def check_permissions() -> bool:
    if hasattr(ctypes, 'windll'):
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def arguments_manager(description: str, commands: dict, arguments: list = None):
    parser = argparse.ArgumentParser(description=description)
    for command, data in commands.items():
        required = data.get('required', False)
        action = data.get('action', None)
        kwargs = dict(action=action, help=data.get('help', None), required=required)
        if data.get('prefix', None) is not None:
            args = data.get('prefix', None), command
            parser.add_argument(*args, **kwargs)
        else:
            parser.add_argument(command, **kwargs)

    return parser.parse_args(args=arguments or None)


def launch_client(host: str, port: int, interface: str):
    if not check_permissions():
        raise Exception('Insufficient Permissions')
    try:
        client = VPNClient((host, port))
        username = input('Username: ')
        client.connect((username, getpass()), interface)
    except Exception as error: print(error)


def server_commands(command: str, vpn_server):
    commands = file['server-commands']
    args = arguments_manager('', commands, command.split())
    user = hasattr(args, 'username') and hasattr(args, 'password')
    if args.add_user and user and hasattr(args, 'network_id'):
        ip = args.ip_address if hasattr(args, 'ip_address') else None
        user = args.username, args.password, args.network_id, ip
        vpn_server.network_manager.accounts.append(list(user))
        print('Created a new account: ', user)
    if args.list_users:
        print('Listing all users: ')
        [print(user) for user in vpn_server.network_manager.accounts]
    if args.add_network and hasattr(args, 'network_range'):
        network_manager = vpn_server.network_manager
        network_id = network_manager.new_network(args.network_range)
        print('New network added:', network_id)
    if args.list_networks:
        networks = vpn_server.network_manager.network
        for network_id, network in networks.items():
            print(network)
            print('Network ID:', network_id)
            print('Connection Limit:', network['max_address'])
            print('Subnet Mask:', network['subnet_mask'])
            print('Network Range:', network['network_range'])
            print('Connections:')
            for connection in network['connections'].items():
                print(connection[1], '=>', connection[0])


def write_command(vpn_server: VPNServer):
    while True:
        command = input('Command: /server ')
        server_commands(command, vpn_server)


def launch_server(host: str, port: int):
    vpn = VPNServer(ip_address=host)
    kwargs = dict(target=write_command, args=(vpn, ))
    threading.Thread(**kwargs, daemon=True).start()
    vpn.run_server(port=port)


if __name__ == '__main__':
    file = json.loads(open('commands.json').read())
    title = '[Python] Simple VPN'

    args = arguments_manager(title, file['main-commands'])
    if args.connect and args.interface:
        launch_client(args.host, int(args.port), args.interface)
    if args.server:
        launch_server(args.host, int(args.port))
