import platform
import subprocess
from typing import Optional


def network_properties(network_range: Optional[tuple or str] = None) -> tuple:
    # Check if the network_range is provided as a tuple.
    if type(network_range) == tuple:
        # Extract the address difference and server address from
        # the tuple.
        address_difference = int(network_range[1].split('.')[-1])
        server_address = int(network_range[0].split('.')[-1])
        # Calculate the subnet mask value based on the address
        # difference.
        value = (address_difference - server_address).bit_length()
        # Update network_range with CIDR notation (e.g., "192.168.1.0/24")
        network_range = network_range[0] + f"/{32 - value}"

    # Set a default network range if none is provided.
    network_range = network_range or "192.168.1.0/24"
    subnet_mask = [0, 0, 0, 0]
    # Iterate through the prefix length to set subnet
    # mask bits.
    for i in range(int(network_range.split('/')[1])):
        subnet_mask[i // 8] |= 1 << (7 - (i % 8))
    # Extract the server IP address from the network range.
    server_ip = network_range.split('/')[0]
    subnet_mask = ".".join(map(str, subnet_mask))
    return server_ip, subnet_mask, network_range


def set_routes(ip_address: str, network_range: Optional[tuple or str] = None) -> None:
    # Get the route, subnet mask, and network range using network_properties function.
    route, subnet_mask, network_range = network_properties(network_range)
    # Define the commands for setting routes on Windows and Linux.
    windows = ["route", "add", route, "mask", subnet_mask, ip_address, "metric", "1"]
    linux = ["sudo", "-S", "ip", "route", "add", network_range, "via", ip_address]
    # Determine the platform and set up keyword arguments for subprocess.run.
    kwargs = dict(shell=True) if platform.system() != 'Linux' else dict()
    subprocess.run(linux if platform.system() == 'Linux' else windows, **kwargs)
