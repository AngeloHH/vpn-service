import json
import logging
import queue
import time
from concurrent.futures import ThreadPoolExecutor
from http import HTTPStatus
from urllib.parse import urlsplit

import h11

logger = logging.getLogger(__name__)


def reason(status: int) -> bytes:
    try: return HTTPStatus(status).phrase.encode()
    except ValueError: return b''


class HTTPRequest:
    def __init__(self, method: str, target: str, version: str,
                 headers: dict[str, str], body: bytes,
                 client: tuple = None, network_id=None):
        location = urlsplit(target)
        self.method, self.target = method, target
        self.version, self.body = version, body
        self.headers = headers
        self.path, self.query = location.path or '/', location.query
        # The tunnel already verified this address belongs to its session.
        self.client, self.network_id = client, network_id

    def header(self, name: str, default: str = None) -> str:
        return self.headers.get(name.lower(), default)

    def json(self):
        return json.loads(self.body.decode()) if self.body else None


class HTTPResponse:
    def __init__(self, body: bytes or str = b'', status: int = 200,
                 headers: dict[str, str] = None):
        if type(body) == str: body = body.encode()
        self.status, self.body = status, body
        self.headers = dict(headers or {})


class StreamResponse:
    # A body produced while the connection stays open; framed as chunked.
    def __init__(self, status: int = 200, headers: dict[str, str] = None):
        self.status, self.headers = status, dict(headers or {})
        self.buffer, self.closed, self.wake = bytearray(), False, None

    def send(self, data: bytes or str):
        if self.closed: return
        self.buffer += data.encode() if type(data) is str else data
        self.notify()

    def close(self):
        if self.closed: return
        self.closed = True
        self.notify()

    def notify(self):
        if self.wake: self.wake()

    def take(self) -> bytes:
        data, self.buffer = bytes(self.buffer), bytearray()
        return data


class EventStream(StreamResponse):
    # Server-Sent Events; a latest event replaces its unsent predecessor.
    def __init__(self, headers: dict[str, str] = None):
        headers = {'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store',
                   **(headers or {})}
        super().__init__(200, headers)
        self.latest = {}

    def event(self, name: str, data, latest: bool = False):
        if self.closed: return
        if type(data) is not str: data = json.dumps(data, separators=(',', ':'))
        lines = ''.join(f'data: {line}\n' for line in data.split('\n'))
        message = f'event: {name}\n{lines}\n'
        if not latest: return self.send(message)
        self.latest[name] = message
        self.notify()

    def comment(self, text: str = ''):
        self.send(f': {text}\n\n')

    def take(self) -> bytes:
        latest, self.latest = ''.join(self.latest.values()).encode(), {}
        return super().take() + latest


class Upgrade:
    # After 101 the TCP byte stream belongs to another protocol, such as
    # WebSocket. The protocol implements receive(bytes), take() and closed.
    def __init__(self, protocol, headers: dict[str, str] = None):
        self.protocol, self.headers = protocol, dict(headers or {})


class Deferred:
    # Slow work runs on a worker thread; finish runs back on the packet loop.
    def __init__(self, work, finish):
        self.work, self.finish = work, finish
        self.response, self.wake = None, None


class HTTPConnection:
    # One h11 state machine per TCP connection: bytes in, bytes out.
    def __init__(self, server: 'VirtualHTTPServer', client: tuple = None,
                 network_id=None, max_request_size: int = 1048576, wake=None):
        self.h11 = h11.Connection(h11.SERVER)
        self.server, self.client, self.network_id = server, client, network_id
        self.max_request_size, self.wake = max_request_size, wake
        self.request, self.body, self.outgoing = None, bytearray(), bytearray()
        self.stream, self.protocol, self.closed = None, None, False
        self.deferred = None

    @property
    def finished(self) -> bool:
        if self.protocol: return self.protocol.closed
        return self.closed or self.h11.our_state in (h11.MUST_CLOSE, h11.CLOSED)

    def receive(self, data: bytes):
        # Empty data means the peer closed its side of the connection.
        if self.protocol: return self.protocol.receive(data)
        if self.closed: return
        self.h11.receive_data(data)
        self._process()

    def take(self) -> bytes:
        # The 101 response leaves before the first bytes of the new protocol.
        if self.protocol: self.outgoing += self.protocol.take()
        elif self.deferred and self.deferred[1].response and not self.closed:
            request, deferred = self.deferred
            self.deferred = None
            self._send(request, deferred.response)
            self._process()
        elif self.stream and not self.closed:
            data = self.stream.take()
            if data: self.outgoing += self.h11.send(h11.Data(data=data))
            if self.stream.closed: self._end_stream()
        output, self.outgoing = bytes(self.outgoing), bytearray()
        return output

    def abort(self):
        self.closed = True
        if self.stream: self.stream.closed = True
        if self.protocol and hasattr(self.protocol, 'abort'): self.protocol.abort()

    def _process(self):
        while not (self.closed or self.stream or self.protocol or self.deferred):
            try: event = self.h11.next_event()
            except h11.RemoteProtocolError as error:
                return self._fail(error.error_status_hint, 'Invalid request')
            if event is h11.NEED_DATA: return
            if event is h11.PAUSED:
                if not self._next_cycle(): return
            elif type(event) is h11.Request: self._start(event)
            elif type(event) is h11.Data:
                self.body += event.data
                if len(self.body) > self.max_request_size:
                    return self._fail(413, 'Request too large')
            elif type(event) is h11.EndOfMessage: self._respond()
            elif type(event) is h11.ConnectionClosed: self.closed = True

    def _start(self, event: h11.Request):
        self.request, self.body = event, bytearray()
        if self.h11.client_is_waiting_for_100_continue:
            self.outgoing += self.h11.send(h11.InformationalResponse(status_code=100, reason=reason(100)))

    def _next_cycle(self) -> bool:
        # Keep-alive: once both sides finished a message, read the next one.
        done = self.h11.our_state is h11.DONE and self.h11.their_state is h11.DONE
        if done: self.h11.start_next_cycle()
        return done

    def _respond(self):
        event = self.request
        headers = {name.decode('latin-1'): value.decode('latin-1')
                   for name, value in event.headers}
        arguments = event.method.decode('ascii'), event.target.decode('latin-1')
        arguments += event.http_version.decode('ascii'), headers, bytes(self.body)
        request = HTTPRequest(*arguments, self.client, self.network_id)
        response = self.server.dispatch(request)
        if type(response) is Deferred:
            self.deferred, response.wake = (request, response), self.wake
            return self.server.submit(response)
        self._send(request, response)

    def _send(self, request: HTTPRequest, response):
        if type(response) is Upgrade: return self._upgrade(request, response)
        status, response_headers = response.status, self._headers(response.headers)
        if isinstance(response, StreamResponse):
            response.wake, self.stream = self.wake, response
            event = h11.Response(status_code=status, headers=response_headers,
                                 reason=reason(status))
            self.outgoing += self.h11.send(event)
            return
        body = b'' if request.method == 'HEAD' else response.body
        # 204 and 304 responses never carry a body or its length.
        if status not in (204, 304):
            response_headers.append(('Content-Length', str(len(response.body))))
        else: body = b''
        event = h11.Response(status_code=status, headers=response_headers, reason=reason(status))
        self.outgoing += self.h11.send(event)
        if body: self.outgoing += self.h11.send(h11.Data(data=body))
        self.outgoing += self.h11.send(h11.EndOfMessage())

    def _upgrade(self, request: HTTPRequest, upgrade: Upgrade):
        if not request.header('upgrade'):
            return self._fail(400, 'The request did not ask for an upgrade')
        headers = self._headers({'Connection': 'Upgrade',
                                 'Upgrade': request.header('upgrade'), **upgrade.headers})
        event = h11.InformationalResponse(status_code=101, headers=headers, reason=reason(101))
        self.outgoing += self.h11.send(event)
        self.protocol = upgrade.protocol
        if hasattr(self.protocol, 'wake'): self.protocol.wake = self.wake
        data, closed = self.h11.trailing_data
        if data: self.protocol.receive(data)
        if closed: self.protocol.receive(b'')

    def _end_stream(self):
        self.outgoing += self.h11.send(h11.EndOfMessage())
        self.stream = None
        if self._next_cycle(): self._process()

    def _fail(self, status: int, message: str):
        # Errors close the connection; h11 rejects a response once one began.
        if self.h11.our_state in (h11.IDLE, h11.SEND_RESPONSE):
            body = message.encode()
            headers = [('Content-Length', str(len(body))), ('Connection', 'close')]
            try:
                event = h11.Response(status_code=status, headers=headers, reason=reason(status))
                self.outgoing += self.h11.send(event)
                self.outgoing += self.h11.send(h11.Data(data=body))
                self.outgoing += self.h11.send(h11.EndOfMessage())
            except h11.LocalProtocolError: pass
        self.closed = True

    @staticmethod
    def _headers(headers: dict[str, str]) -> list[tuple[str, str]]:
        return [(name, value) for name, value in headers.items()
                if name.lower() not in ('content-length', 'transfer-encoding')]


class VirtualHTTPServer:
    def __init__(self, workers: int = 2):
        # Routes are application state; requests and responses remain bytes.
        self.routes, self.timers = {}, []
        # Deferred work ends on worker threads and returns through a queue.
        self.workers, self.executor = workers, None
        self.completed, self.notify = queue.SimpleQueue(), None

    def add_route(self, method: str, path: str, handler):
        route = method.upper(), path
        if route in self.routes: raise ValueError('HTTP route already exists')
        self.routes[route] = handler

    def route(self, method: str, path: str):
        def register(handler):
            self.add_route(method, path, handler)
            return handler
        return register

    def every(self, interval: float, callback=None):
        # Timers run from the packet loop, so callbacks must stay short.
        if callback is None: return lambda handler: self.every(interval, handler)
        self.timers.append([interval, time.monotonic() + interval, callback])
        return callback

    def run_timers(self, now: float = None):
        now = time.monotonic() if now is None else now
        for timer in self.timers:
            if timer[1] > now: continue
            timer[1] = now + timer[0]
            try: timer[2]()
            except Exception: logger.exception('Virtual HTTP timer failed')

    def next_timer(self, now: float = None):
        if not self.completed.empty(): return 0.0
        now = time.monotonic() if now is None else now
        delays = [max(0.0, timer[1] - now) for timer in self.timers]
        return min(delays) if delays else None

    def submit(self, deferred: Deferred):
        if not self.executor:
            self.executor = ThreadPoolExecutor(self.workers, 'virtual-http')
        future = self.executor.submit(deferred.work)
        future.add_done_callback(lambda future: self._completed(deferred, future))

    def _completed(self, deferred: Deferred, future):
        # Worker thread: only queue the result and wake the packet loop.
        self.completed.put((deferred, future))
        if self.notify: self.notify()

    def run_completions(self, timeout: float = None) -> int:
        # Finish callbacks run here, on the packet loop, never on a worker.
        count = 0
        while True:
            block = timeout is not None and count == 0
            try: deferred, future = self.completed.get(block, timeout)
            except queue.Empty: return count
            try: response = deferred.finish(future.result())
            except Exception:
                logger.exception('Virtual HTTP deferred work failed')
                response = HTTPResponse('Internal Server Error', 500)
            response = self.normalize(response)
            if type(response) is Deferred: response = HTTPResponse('Internal Server Error', 500)
            deferred.response = response
            if deferred.wake: deferred.wake()
            count += 1

    @staticmethod
    def normalize(response):
        responses = HTTPResponse, StreamResponse, Upgrade, Deferred
        return response if isinstance(response, responses) else HTTPResponse(response)

    def dispatch(self, request: HTTPRequest):
        method = 'GET' if request.method == 'HEAD' else request.method
        handler = self.routes.get((method, request.path))
        if not handler: return HTTPResponse('Not Found', 404)
        # A failing handler answers 500 instead of stopping the packet loop.
        try: response = handler(request)
        except Exception:
            logger.exception('Virtual HTTP handler failed')
            return HTTPResponse('Internal Server Error', 500)
        return self.normalize(response)

    def handle(self, request: bytes, client: tuple = ('virtual', 0),
               network_id=None) -> bytes:
        # Serve one complete request outside a TCP connection.
        connection = HTTPConnection(self, client, network_id)
        connection.receive(request)
        waiting = lambda: connection.deferred and not connection.deferred[1].response
        while waiting() and self.run_completions(timeout=5): pass
        connection.receive(b'')
        return connection.take()
