import unittest

import threading

from connection.virtual_http import (Deferred, EventStream, HTTPConnection, HTTPResponse,
                                     StreamResponse, Upgrade, VirtualHTTPServer)


def get(path: str, *headers: str) -> bytes:
    lines = ''.join(f'{header}\r\n' for header in headers)
    return f'GET {path} HTTP/1.1\r\nHost: 192.168.1.1\r\n{lines}\r\n'.encode()


class Echo:
    # A minimal protocol that answers every byte after the upgrade.
    def __init__(self): self.output, self.closed, self.wake = bytearray(), False, None
    def receive(self, data):
        if not data: self.closed = True
        self.output += data
    def take(self):
        data, self.output = bytes(self.output), bytearray()
        return data


class VirtualHTTPTest(unittest.TestCase):
    def test_handles_http_without_a_tcp_connection(self):
        server = VirtualHTTPServer()

        @server.route('GET', '/')
        def index(request):
            return HTTPResponse('Virtual router', headers={
                'Content-Type': 'text/plain; charset=utf-8'
            })

        request = b'GET / HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n'
        response = server.handle(request)

        self.assertTrue(response.startswith(b'HTTP/1.1 200 OK\r\n'))
        self.assertTrue(response.endswith(b'\r\n\r\nVirtual router'))
        self.assertIn(b'Content-Length: 14\r\n', response)

    def test_passes_the_request_body_and_query(self):
        server = VirtualHTTPServer()

        def update(request):
            body = request.query.encode() + b':' + request.body
            return HTTPResponse(body, status=201)

        server.add_route('POST', '/network', update)
        request = (
            b'POST /network?mode=automatic HTTP/1.1\r\n'
            b'Host: 192.168.1.1\r\nContent-Length: 7\r\n\r\n'
            b'enabled'
        )
        response = server.handle(request)

        self.assertTrue(response.startswith(b'HTTP/1.1 201 Created\r\n'))
        self.assertTrue(response.endswith(b'\r\n\r\nmode=automatic:enabled'))

    def test_returns_not_found_for_an_unknown_route(self):
        server = VirtualHTTPServer()
        request = b'GET /missing HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n'
        response = server.handle(request)

        self.assertTrue(response.startswith(b'HTTP/1.1 404 Not Found\r\n'))
        self.assertTrue(response.endswith(b'\r\n\r\nNot Found'))

    def test_rejects_an_incomplete_request_body(self):
        server = VirtualHTTPServer()
        request = (
            b'POST /network HTTP/1.1\r\nHost: 192.168.1.1\r\n'
            b'Content-Length: 7\r\n\r\nshort'
        )
        response = server.handle(request)

        self.assertTrue(response.startswith(b'HTTP/1.1 400 Bad Request\r\n'))


class ConnectionTest(unittest.TestCase):
    def setUp(self):
        self.server, self.woken = VirtualHTTPServer(), []
        self.server.add_route('GET', '/', lambda request: 'index')
        self.server.add_route('GET', '/other', lambda request: 'other')
        self.connection = HTTPConnection(self.server, ('10.0.0.2', 40000), 'network',
                                         max_request_size=16,
                                         wake=lambda: self.woken.append(True))

    def exchange(self, data: bytes) -> bytes:
        self.connection.receive(data)
        return self.connection.take()

    def test_one_connection_serves_several_requests(self):
        first = self.exchange(get('/'))
        self.assertTrue(first.endswith(b'\r\n\r\nindex'))
        self.assertFalse(self.connection.finished)
        self.assertTrue(self.exchange(get('/other')).endswith(b'\r\n\r\nother'))

    def test_pipelined_requests_are_answered_in_order(self):
        response = self.exchange(get('/other') + get('/'))
        self.assertLess(response.index(b'other'), response.rindex(b'index'))

    def test_connection_close_is_honoured(self):
        self.exchange(get('/', 'Connection: close'))
        self.assertTrue(self.connection.finished)

    def test_head_uses_the_get_route_without_a_body(self):
        response = self.exchange(get('/').replace(b'GET', b'HEAD', 1))
        self.assertIn(b'Content-Length: 5\r\n', response)
        self.assertTrue(response.endswith(b'\r\n\r\n'))

    def test_a_chunked_request_body_is_assembled(self):
        bodies = []
        self.server.add_route('POST', '/', lambda request: bodies.append(request.body) or '')
        request = (b'POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n'
                   b'3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n')
        self.assertIn(b'HTTP/1.1 200 OK', self.exchange(request))
        self.assertEqual(bodies, [b'abcde'])

    def test_a_large_body_is_rejected_and_closed(self):
        request = b'POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 64\r\n\r\n' + b'x' * 64
        self.assertIn(b'HTTP/1.1 413 ', self.exchange(request))
        self.assertTrue(self.connection.finished)

    def test_a_failing_handler_answers_500(self):
        self.server.add_route('GET', '/fail', lambda request: 1 / 0)
        with self.assertLogs('connection.virtual_http'):
            response = self.exchange(get('/fail'))
        self.assertIn(b'HTTP/1.1 500 Internal Server Error', response)
        self.assertTrue(self.exchange(get('/')).endswith(b'index'))

    def test_a_stream_stays_open_and_then_frees_the_connection(self):
        stream = StreamResponse(headers={'Content-Type': 'text/plain'})
        self.server.add_route('GET', '/stream', lambda request: stream)
        headers = self.exchange(get('/stream'))
        self.assertIn(b'Transfer-Encoding: chunked', headers)
        stream.send('hello')
        self.assertEqual(self.woken, [True])
        self.assertEqual(self.connection.take(), b'5\r\nhello\r\n')
        stream.close()
        self.assertEqual(self.connection.take(), b'0\r\n\r\n')
        self.assertTrue(self.exchange(get('/')).endswith(b'index'))

    def test_a_request_waits_while_a_stream_is_open(self):
        stream = StreamResponse()
        self.server.add_route('GET', '/stream', lambda request: stream)
        self.exchange(get('/stream') + get('/'))
        self.assertNotIn(b'index', self.connection.take())
        stream.close()
        self.assertTrue(self.connection.take().endswith(b'index'))

    def test_server_sent_events_keep_only_the_latest_unsent_status(self):
        stream = EventStream()
        stream.event('log', 'first'), stream.event('log', 'second')
        stream.event('status', {'cpu': 1}, latest=True)
        stream.event('status', {'cpu': 2}, latest=True)
        self.assertEqual(stream.take(), b'event: log\ndata: first\n\n'
                                        b'event: log\ndata: second\n\n'
                                        b'event: status\ndata: {"cpu":2}\n\n')
        self.assertEqual(stream.headers['Content-Type'], 'text/event-stream')

    def test_an_upgrade_hands_the_bytes_to_another_protocol(self):
        echo = Echo()
        self.server.add_route('GET', '/echo', lambda request: Upgrade(echo))
        request = get('/echo', 'Connection: Upgrade', 'Upgrade: echo') + b'early'
        response = self.exchange(request)
        self.assertTrue(response.startswith(b'HTTP/1.1 101 Switching Protocols'))
        self.assertTrue(response.endswith(b'\r\n\r\nearly'))
        self.assertEqual(self.exchange(b'raw bytes'), b'raw bytes')
        self.connection.receive(b'')
        self.assertTrue(self.connection.finished)

    def test_an_upgrade_needs_the_request_to_ask_for_it(self):
        self.server.add_route('GET', '/echo', lambda request: Upgrade(Echo()))
        self.assertIn(b'HTTP/1.1 400 Bad Request', self.exchange(get('/echo')))

    def test_an_aborted_connection_closes_its_stream(self):
        stream = StreamResponse()
        self.server.add_route('GET', '/stream', lambda request: stream)
        self.exchange(get('/stream'))
        self.connection.abort()
        self.assertTrue(stream.closed)

    def test_the_request_knows_its_client_and_network(self):
        requests = []
        self.server.add_route('GET', '/who', lambda request: requests.append(request) or '')
        self.exchange(get('/who', 'X-Custom: yes'))
        self.assertEqual((requests[0].client, requests[0].network_id),
                         (('10.0.0.2', 40000), 'network'))
        self.assertEqual(requests[0].header('X-CUSTOM'), 'yes')


class DeferredTest(unittest.TestCase):
    def setUp(self):
        self.server, self.notified, self.threads = VirtualHTTPServer(), [], {}
        self.server.notify = lambda: self.notified.append(threading.current_thread())
        self.server.add_route('GET', '/', lambda request: 'index')

    def deferred(self, request):
        def work():
            self.threads['work'] = threading.current_thread()
            return 'slow'

        def finish(result):
            self.threads['finish'] = threading.current_thread()
            return HTTPResponse(result)
        return Deferred(work, finish)

    def test_slow_work_runs_on_a_worker_and_finishes_on_the_loop(self):
        self.server.add_route('GET', '/slow', self.deferred)
        connection = HTTPConnection(self.server)
        connection.receive(get('/slow') + get('/'))
        self.assertEqual(connection.take(), b'')
        self.assertEqual(self.server.run_completions(timeout=5), 1)
        response = connection.take()
        self.assertLess(response.index(b'slow'), response.rindex(b'index'))
        self.assertIsNot(self.threads['work'], threading.main_thread())
        self.assertIs(self.threads['finish'], threading.main_thread())
        self.assertEqual(len(self.notified), 1)

    def test_failing_work_answers_500(self):
        self.server.add_route('GET', '/slow', lambda request: Deferred(lambda: 1 / 0, str))
        with self.assertLogs('connection.virtual_http'):
            response = self.server.handle(get('/slow'))
        self.assertIn(b'HTTP/1.1 500 Internal Server Error', response)

    def test_a_pending_completion_wakes_the_loop_now(self):
        self.server.add_route('GET', '/slow', self.deferred)
        connection = HTTPConnection(self.server)
        connection.receive(get('/slow'))
        while self.server.completed.empty(): pass
        self.assertEqual(self.server.next_timer(), 0)


class TimerTest(unittest.TestCase):
    def test_timers_run_when_due(self):
        server, calls = VirtualHTTPServer(), []
        server.every(1, lambda: calls.append(True))
        start = server.timers[0][1] - 1
        server.run_timers(start + 0.5)
        self.assertEqual(calls, [])
        self.assertAlmostEqual(server.next_timer(start + 0.5), 0.5)
        server.run_timers(start + 1)
        self.assertEqual(calls, [True])

    def test_a_failing_timer_does_not_stop_the_others(self):
        server, calls = VirtualHTTPServer(), []
        server.every(0, lambda: 1 / 0)
        server.every(0, lambda: calls.append(True))
        with self.assertLogs('connection.virtual_http'): server.run_timers()
        self.assertEqual(calls, [True])


if __name__ == '__main__': unittest.main()
