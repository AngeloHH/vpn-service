import argparse
import signal
import sys
import threading
from getpass import getpass

from connection.errors import VPNError
from connection.vpn_service import VPNClient

PORT = 5732
# The account has no networks and the person chose to wait.
WAITING = 3


class Terminal:
    """Everything the commands read or show, so another interface can replace it."""

    def __init__(self, ask=input, secret=getpass, show=print, error=None, interactive=None):
        self.ask, self.secret, self.show = ask, secret, show
        self.error = error or (lambda text: print(text, file=sys.stderr))
        self.interactive = sys.stdin.isatty() if interactive is None else interactive

    def confirm(self, question: str) -> bool:
        if not self.interactive: return False
        return self.ask(f'{question} [y/N] ').strip().lower() in ('y', 'yes')


def address(text: str) -> tuple:
    host, _, port = text.rpartition(':') if ':' in text else (text, '', str(PORT))
    try: port = int(port)
    except ValueError: raise argparse.ArgumentTypeError('the port must be a number')
    if not host or not 0 < port < 65536: raise argparse.ArgumentTypeError('expected host or host:port')
    return host, port


def password(options, terminal: Terminal, repeat: bool = False) -> str:
    # From the keyboard, or one line of standard input for scripts.
    if options.password_stdin: value = sys.stdin.readline().rstrip('\n')
    else:
        value = terminal.secret('Password: ')
        if repeat and value != terminal.secret('Repeat the password: '): raise VPNError('passwords_differ')
    # Kept for the login right after registering, never written anywhere.
    options.typed = value
    return value


def logged_in(options, terminal: Terminal, client_class) -> VPNClient:
    client = client_class(options.server)
    client.authenticate(options.username, password(options, terminal))
    return client


def found(client: VPNClient, name: str, terminal: Terminal) -> dict:
    created = client.create_organization(name)
    terminal.show(f'Created the organization {name.strip()}; you administer it.')
    return created


def without_networks(client: VPNClient, terminal: Terminal, name: str = None) -> bool:
    # The same choice after registering or logging in: found an organization or wait.
    if name: return bool(found(client, name, terminal))
    terminal.error(VPNError('no_networks').message)
    if not terminal.confirm('Create an organization now?'): return False
    return bool(found(client, terminal.ask('Organization name: '), terminal))


def show_networks(networks: list, terminal: Terminal):
    for network in networks:
        mark = '*' if network.get('default') else ' '
        terminal.show(f"{mark} {network['network_id']}  {network['network_range']:<18} {network['ip_address']}")


def register(options, terminal: Terminal, client_class) -> int:
    client = client_class(options.server)
    client.register(options.username, options.email, password(options, terminal, repeat=True))
    terminal.show(f'Created the account {options.username}.')
    # The new account logs in at once; the password was already read.
    client.authenticate(options.username, options.typed)
    if without_networks(client, terminal, options.create_organization): return 0
    terminal.show(f'An administrator can add {options.email} to an organization.')
    return WAITING


def networks(options, terminal: Terminal, client_class) -> int:
    found_networks = logged_in(options, terminal, client_class).list_networks()
    if not found_networks:
        terminal.error(VPNError('no_networks').message)
        return WAITING
    show_networks(found_networks, terminal)
    return 0


def organization(options, terminal: Terminal, client_class) -> int:
    found(logged_in(options, terminal, client_class), options.name, terminal)
    return 0


def connect(options, terminal: Terminal, client_class) -> int:
    client = logged_in(options, terminal, client_class)
    if not client.list_networks() and not without_networks(client, terminal, options.create_organization):
        return WAITING
    terminal.show('Connecting. Press Ctrl+C to disconnect.')
    # Being stopped by the system (kill, a service manager) ends as cleanly as Ctrl+C.
    previous = {}
    if threading.current_thread() is threading.main_thread():
        for name in ('SIGINT', 'SIGTERM', 'SIGHUP'):
            if hasattr(signal, name): previous[name] = signal.signal(getattr(signal, name), interrupted)
    # The client removes its addresses and routes however the tunnel ends.
    try: client.connect(interface=options.interface, network_id=options.network)
    except KeyboardInterrupt: terminal.show('Disconnected.')
    finally:
        for name, handler in previous.items(): signal.signal(getattr(signal, name), handler)
    return 0


def interrupted(number, frame):
    raise KeyboardInterrupt


def add_commands(commands):
    def command(name, handler, text, *arguments):
        parser = commands.add_parser(name, help=text)
        parser.add_argument('server', type=address, help='host or host:port of the VPN server')
        parser.add_argument('username')
        for argument in arguments: parser.add_argument(*argument[0], **argument[1])
        parser.add_argument('--password-stdin', action='store_true', help='read the password from standard input')
        parser.set_defaults(handler=handler)
        return parser

    create = (('--create-organization',), dict(metavar='NAME', help='found this organization if the account has no networks'))
    command('register', register, 'create an account on a public server',
            (('email',), {}), create)
    command('networks', networks, 'list the networks of an account')
    command('organization', organization, 'found an organization and administer it',
            (('name',), {}))
    command('connect', connect, 'connect to a network (needs a TUN driver)',
            (('--interface',), dict(default='vpn0')),
            (('--network',), dict(metavar='ID', help='network to enter; the default one otherwise')), create)


def run(options, terminal: Terminal = None, client_class=VPNClient) -> int:
    # Every refusal is a VPNError: it is shown with its code and ends the command.
    terminal = terminal or Terminal()
    try: return options.handler(options, terminal, client_class)
    except VPNError as error:
        terminal.error(f'Error: {error.message} ({error.code})')
        return 1
