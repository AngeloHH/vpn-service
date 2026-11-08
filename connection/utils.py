import platform
import subprocess
from typing import Optional


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


def configure_networks(interface: str, networks: list[dict]) -> None:
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
