import argparse
import ctypes
import json
import os
import threading
from getpass import getpass

from pymongo import MongoClient

from connection import VPNClient, VPNServer
from connection.network import Manager


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


def server_commands(args, net_manager: Manager):
    user = hasattr(args, 'username') and hasattr(args, 'password')
    if args.add_user and user and hasattr(args, 'network_id'):
        user_id = net_manager.new_account(args.username, args.password)
        print('Created a new account: ', user_id)
    if args.list_users:
        print('Listing all users: ')
        [print(user) for user in net_manager.list_accounts()]
    if args.add_network and hasattr(args, 'network_range'):
        network_id = net_manager.new_network(args.network_range, 5)
        print('New network added:', network_id)
    if args.list_networks:
        for network in net_manager.list_networks():
            print('Network ID:', network['_id'])
            print('Connection Limit:', network['max_address'])
            print('Subnet Mask:', network['subnet_mask'])
            print('Network Range:', network['network_range'])
            print('Connections:')
            for connection in network['connections'].items():
                print(connection[0], '=>', connection[1])


def launch_server(commands: dict, host: str, port: int):
    mongo_client = MongoClient("mongodb://localhost:27017/")
    vpn = VPNServer(mongo_client, 'test_network')
    vpn.ip_address, manager = host, vpn.network_manager
    server = threading.Thread(target=vpn.run_server, args=(port, ), daemon=True)
    server.start()
    while True:
        command = input('Command: /server ').split()
        details = ''
        server_commands(arguments_manager(details, commands, command), manager)


def main(command_file):
    file = json.loads(open(command_file).read())
    title = '[Python] Simple VPN'

    args = arguments_manager(title, file['main-commands'])
    if args.connect and args.interface:
        launch_client(args.host, int(args.port), args.interface)
    if args.server:
        commands = file['server-commands']
        launch_server(commands, args.host, int(args.port))
