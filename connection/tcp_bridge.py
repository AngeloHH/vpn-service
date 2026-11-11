import logging

from tcp_sansio import TCPStack

from connection.virtual_http import HTTPConnection, VirtualHTTPServer

logger = logging.getLogger(__name__)


class HTTPLink:
    def __init__(self, connection, http: HTTPConnection):
        self.connection, self.http = connection, http
        self.pending, self.eof = bytearray(), False


class VirtualHTTPBridge:
    def __init__(self, network_id, ip_address: str, port: int = 80,
                 server: VirtualHTTPServer = None, mtu: int = 1420,
                 max_request_size: int = 1048576):
        self.network_id, self.ip_address = network_id, ip_address
        self.port, self.server = port, server or VirtualHTTPServer()
        self.max_request_size = max_request_size
        self.stack, self.links = TCPStack(ip_address, mtu), {}
        # Streams wake their links when new output exists without TCP events.
        self.awake = set()
        self.listener = self.stack.listen(port)

    def _accept(self):
        while True:
            connection = self.listener.accept()
            if not connection: return
            client = connection.remote_address or ('virtual', 0)
            wake = lambda key=connection.id: self.awake.add(key)
            arguments = self.server, client, self.network_id, self.max_request_size
            http = HTTPConnection(*arguments, wake=wake)
            self.links[connection.id] = HTTPLink(connection, http)

    def _discard(self, link: HTTPLink):
        link.http.abort()
        link.connection.abort(), link.connection.release()
        self.links.pop(link.connection.id, None)

    def _flush(self, link: HTTPLink):
        # Pull new output only after TCP accepted the previous bytes.
        if not link.connection.can_send: return self._discard(link)
        if not link.pending: link.pending += link.http.take()
        if link.pending:
            sent = link.connection.send(bytes(link.pending))
            del link.pending[:sent]
        if link.pending or not link.http.finished: return
        link.connection.close(), link.connection.release()
        self.links.pop(link.connection.id, None)

    def _read(self, link: HTTPLink, event):
        data = link.connection.receive() if event.readable else b''
        if data: link.http.receive(data)
        if event.eof and not link.eof:
            link.eof = True
            link.http.receive(b'')

    def _process(self):
        self._accept()
        touched = set()
        for event in self.stack.events():
            link = self.links.get(event.connection.id)
            if not link: continue
            reset = event.eof and not event.connection.can_send
            if reset:
                self._discard(link)
                continue
            # A failing connection is dropped; the packet loop keeps running.
            try: self._read(link, event)
            except Exception:
                logger.exception('Virtual HTTP connection failed')
                self._discard(link)
                continue
            touched.add(link.connection.id)
        touched |= self.awake
        self.awake.clear()
        for key in touched:
            link = self.links.get(key)
            if not link: continue
            try: self._flush(link)
            except Exception:
                logger.exception('Virtual HTTP connection failed')
                self._discard(link)

    def receive(self, packet: bytes, timestamp: float = None) -> list[bytes]:
        self.stack.receive(packet, timestamp)
        self._process()
        return self.stack.transmit(timestamp)

    def advance(self, timestamp: float = None) -> list[bytes]:
        self.server.run_completions()
        self.server.run_timers()
        self.stack.advance(timestamp)
        self._process()
        return self.stack.transmit(timestamp)

    def next_timeout(self, timestamp: float = None):
        delays = [self.stack.next_timeout(timestamp), self.server.next_timer()]
        delays = [delay for delay in delays if delay is not None]
        return min(delays) if delays else None

    def close(self) -> list[bytes]:
        for link in self.links.values(): link.http.abort()
        self.links.clear()
        return self.stack.close()
