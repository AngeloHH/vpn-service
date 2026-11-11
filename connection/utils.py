import logging
import platform
import socket
import subprocess
from ipaddress import ip_address as parse_address
from typing import Optional

# Two halves of the address space beat the default route without replacing it.
INTERNET = '0.0.0.0/1', '128.0.0.0/1'
logger = logging.getLogger(__name__)


def network_properties(network_range: Optional[tuple or str] = None) -> tuple:
    if type(network_range) == tuple:
        # Derive the prefix size from the distance between endpoint octets.
        address_difference = int(network_range[1].split('.')[-1])
        server_address = int(network_range[0].split('.')[-1])
        value = (address_difference - server_address).bit_length()
        network_range = network_range[0] + f"/{32 - value}"

    network_range = network_range or "192.168.1.0/24"
    subnet_mask = [0, 0, 0, 0]
    # Fill prefix bits from the most significant position downward.
    for i in range(int(network_range.split('/')[1])):
        subnet_mask[i // 8] |= 1 << (7 - (i % 8))
    server_ip = network_range.split('/')[0]
    subnet_mask = ".".join(map(str, subnet_mask))
    return server_ip, subnet_mask, network_range


def prefix_length(subnet_mask: str) -> int:
    return sum(bin(int(octet)).count('1') for octet in subnet_mask.split('.'))


def set_address(interface: str, ip_address: str, subnet_mask: str) -> None:
    prefix = prefix_length(subnet_mask)
    commands = {
        'Linux': ['ip', 'address', 'add', f'{ip_address}/{prefix}',
                  'dev', interface],
        'Windows': ['netsh', 'interface', 'ipv4', 'add', 'address',
                    f'name={interface}', f'address={ip_address}',
                    f'mask={subnet_mask}'],
        'Darwin': ['ifconfig', interface, 'alias', ip_address,
                   'netmask', subnet_mask]
    }
    subprocess.run(commands[platform.system()], check=True)


def set_routes(ip_address: str, network_range: Optional[tuple or str] = None,
               interface: str = None) -> None:
    route, subnet_mask, network_range = network_properties(network_range)
    windows = ['route', 'add', route, 'mask', subnet_mask,
               ip_address, 'metric', '1']
    if interface:
        linux = ['ip', 'route', 'replace', network_range, 'dev', interface,
                 'src', ip_address]
        darwin = ['route', '-n', 'add', '-net', network_range,
                  '-interface', interface]
    else:
        linux = ['ip', 'route', 'replace', network_range, 'via', ip_address]
        darwin = ['route', '-n', 'add', '-net', network_range, ip_address]
    commands = dict(Linux=linux, Windows=windows, Darwin=darwin)
    subprocess.run(commands[platform.system()], check=True)


def server_route(server_address: str) -> list:
    # The command that keeps the tunnel's own packets on their current path.
    system = platform.system()
    if system == 'Windows':
        script = (f"$route = Find-NetRoute -RemoteIPAddress '{server_address}' | "
                  "Where-Object { $_.NextHop } | Select-Object -First 1; "
                  f"New-NetRoute -DestinationPrefix '{server_address}/32' "
                  "-InterfaceIndex $route.InterfaceIndex -NextHop $route.NextHop "
                  "-RouteMetric 1 -PolicyStore ActiveStore | Out-Null")
        return ['powershell', '-NoProfile', '-Command', script]
    if system == 'Linux':
        found = subprocess.run(['ip', 'route', 'get', server_address], capture_output=True,
                               text=True, check=True).stdout.split()
        route = ['ip', 'route', 'replace', f'{server_address}/32']
        if 'via' in found: route += ['via', found[found.index('via') + 1]]
        return route + ['dev', found[found.index('dev') + 1]]
    lines = subprocess.run(['route', '-n', 'get', server_address], capture_output=True,
                           text=True, check=True).stdout.splitlines()
    fields = dict(line.strip().split(': ', 1) for line in lines if ': ' in line)
    if 'gateway' in fields: return ['route', '-n', 'add', '-host', server_address, fields['gateway']]
    return ['route', '-n', 'add', '-host', server_address, '-interface', fields['interface']]


def set_internet(interface: str, ip_address: str, server_address: str) -> None:
    # The route to the server goes first, or the tunnel would carry itself.
    server_address = socket.gethostbyname(server_address)
    if not parse_address(server_address).is_loopback:
        subprocess.run(server_route(server_address), check=True)
    for prefix in INTERNET: set_routes(ip_address, prefix, interface)


def remove_internet(interface: str, server_address: str) -> None:
    for prefix in INTERNET: remove_routes(prefix, interface)
    server_address = socket.gethostbyname(server_address)
    if parse_address(server_address).is_loopback: return
    commands = dict(
        Linux=['ip', 'route', 'del', f'{server_address}/32'],
        Windows=['powershell', '-NoProfile', '-Command',
                 f"Remove-NetRoute -DestinationPrefix '{server_address}/32' "
                 "-Confirm:$false -ErrorAction SilentlyContinue"],
        Darwin=['route', '-n', 'delete', '-host', server_address]
    )
    subprocess.run(commands[platform.system()], capture_output=True)


def set_dns(interface: str, servers: list, internet: bool) -> None:
    # The network's DNS servers go on the virtual card while the connection lasts.
    system = platform.system()
    if system == 'Windows':
        name = f'name={interface}'
        commands = [['netsh', 'interface', 'ipv4', 'set', 'dnsservers', name, 'source=static',
                     f'address={servers[0]}', 'register=none', 'validate=no']]
        commands += [['netsh', 'interface', 'ipv4', 'add', 'dnsservers', name,
                      f'address={server}', f'index={index}', 'validate=no']
                     for index, server in enumerate(servers[1:], 2)]
    elif system == 'Linux':
        # With internet through the VPN, every name is resolved through it too.
        commands = [['resolvectl', 'dns', interface, *servers]]
        if internet: commands.append(['resolvectl', 'domain', interface, '~.'])
    else:
        logger.warning('The network DNS servers are not applied on %s', system)
        return
    try:
        for command in commands: subprocess.run(command, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        # Without resolvectl (no systemd-resolved) the connection still works.
        logger.warning('The network DNS servers could not be applied')


def clear_dns(interface: str) -> None:
    commands = dict(
        Linux=['resolvectl', 'revert', interface],
        Windows=['netsh', 'interface', 'ipv4', 'set', 'dnsservers', f'name={interface}',
                 'source=static', 'address=none', 'validate=no']
    )
    if platform.system() not in commands: return
    try: subprocess.run(commands[platform.system()], capture_output=True)
    except OSError: pass


def configure_networks(interface: str, networks: list[dict],
                       server_address: str = None) -> None:
    # One TUN owns every lease; routed networks only add a preferred route.
    addresses = {network['ip_address'] for network in networks}
    for network in networks:
        assigned = network['mode'] == 'assigned' and not network['primary']
        if assigned:
            arguments = interface, network['ip_address'], network['subnet_mask']
            set_address(*arguments)
    for network in networks:
        arguments = network['ip_address'], network['network_range'], interface
        set_routes(*arguments)
        for route in network['routes']:
            if route.split('/')[0] in addresses: continue
            arguments = network['ip_address'], route, interface
            set_routes(*arguments)
    # A network with internet access takes every destination outside the others.
    primary = next(network for network in networks if network['primary'])
    internet = any(network.get('internet') for network in networks)
    if server_address and internet:
        set_internet(interface, primary['ip_address'], server_address)
    # One card, one DNS list: the network this connection chose.
    if primary.get('dns'): set_dns(interface, primary['dns'], internet)


def remove_address(interface: str, ip_address: str, subnet_mask: str) -> None:
    prefix = prefix_length(subnet_mask)
    commands = {
        'Linux': ['ip', 'address', 'del', f'{ip_address}/{prefix}',
                  'dev', interface],
        'Windows': ['netsh', 'interface', 'ipv4', 'delete', 'address',
                    f'name={interface}', f'address={ip_address}'],
        'Darwin': ['ifconfig', interface, '-alias', ip_address]
    }
    subprocess.run(commands[platform.system()], capture_output=True)


def remove_routes(network_range: str, interface: str) -> None:
    route, subnet_mask, network_range = network_properties(network_range)
    commands = dict(
        Linux=['ip', 'route', 'del', network_range, 'dev', interface],
        Windows=['route', 'delete', route, 'mask', subnet_mask],
        Darwin=['route', '-n', 'delete', '-net', network_range]
    )
    subprocess.run(commands[platform.system()], capture_output=True)


def remove_networks(interface: str, networks: list[dict],
                    server_address: str = None) -> None:
    # Undo configure_networks; entries already gone are not an error.
    if any(network.get('dns') for network in networks): clear_dns(interface)
    if server_address and any(network.get('internet') for network in networks):
        remove_internet(interface, server_address)
    addresses = {network['ip_address'] for network in networks}
    for network in networks:
        for route in network['routes']:
            if route.split('/')[0] in addresses: continue
            remove_routes(route, interface)
        remove_routes(network['network_range'], interface)
    for network in networks:
        assigned = network['mode'] == 'assigned' and not network['primary']
        if assigned:
            arguments = interface, network['ip_address'], network['subnet_mask']
            remove_address(*arguments)
