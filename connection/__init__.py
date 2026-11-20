PROJECT, __version__ = 'vpn-service', '0.1.0'

from .session import NetworkAccess, Session, SessionRegistry
from .tcp_bridge import VirtualHTTPBridge
from .utils import configure_networks, network_properties, set_routes
from .virtual_http import HTTPRequest, HTTPResponse, VirtualHTTPServer
from .errors import MESSAGES, VPNError
from .vpn_service import VPNServer, VPNClient
