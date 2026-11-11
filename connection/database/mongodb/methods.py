def network_properties(network_range: tuple or str = None) -> tuple:
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
