from pathlib import Path

from connection.admin.api import register_api
from connection.admin.static import register_static
from connection.virtual_http import VirtualHTTPServer

WEB = Path(__file__).parent / 'web'


def register_admin(http: VirtualHTTPServer, vpn_server=None):
    register_static(http, WEB)
    if vpn_server: register_api(http, vpn_server)
    return http
