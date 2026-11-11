from ipaddress import ip_network

from bson import ObjectId


def capacity(document: dict) -> int:
    network = ip_network(document['network_range'], strict=False)
    hosts = network.num_addresses - (2 if network.prefixlen < 31 else 0)
    return min(document.get('max_address') or hosts, hosts)


def summary(document: dict) -> dict:
    # Stored fields the panel may show; individual leases stay private.
    connections, routes = document.get('connections', {}), document.get('routes', {})
    router = (document.get('server') or {}).get('ip_address')
    members = len(connections) + len(routes)
    return dict(id=document['_id'].__str__(), name=document.get('name'),
                network_range=document['network_range'], subnet_mask=document['subnet_mask'],
                router=router, members=members, used=members + bool(router),
                capacity=capacity(document), max_address=document['max_address'],
                assigned=len(connections), internet=document.get('internet') is True,
                dns=document.get('dns') or [])


def read_networks(collection, organization_id):
    # Runs on a worker thread: the database read never blocks the packet loop.
    def work() -> list[dict]:
        documents = collection.find({'organization_id': organization_id})
        return sorted((summary(document) for document in documents),
                      key=lambda network: network['id'])
    return work


# What the panel may offer on each network; the server checks again on write.
ACTIONS = dict(modify='networks:modify', delete='networks:delete',
               view_addresses='addresses:view', add_address='addresses:add',
               modify_address='addresses:modify', delete_address='addresses:delete')


def visible(session, networks: list[dict], allowed) -> list[dict]:
    # Unnamed networks keep their position number even when others are hidden.
    result, permissions = [], session.permissions
    primary = permissions.primary if permissions else None
    for number, network in enumerate(networks, 1):
        if not allowed(session, network['id'], 'networks:view'): continue
        access = session.networks.get(ObjectId(network['id']))
        can = {name: allowed(session, network['id'], permission)
               for name, permission in ACTIONS.items()}
        result.append(dict(network, number=number,
                           your_ip=access.ip_address if access else None,
                           primary=network['id'] == primary, can=can))
    return result
