import ctypes
import hashlib
import os
import pickle
import socket
import struct

from connection.protocol import Protocol

# Linux: a group of sockets on one UDP port, and a filter that picks which one gets each datagram.
SO_ATTACH_REUSEPORT_CBPF = 51


def available() -> bool:
    return hasattr(socket, 'SO_REUSEPORT') and os.name == 'posix' and os.uname().sysname == 'Linux'


def owner(organization_id, workers: int) -> int:
    # The same answer in every process, without asking anyone: organizations never move.
    if workers <= 1 or organization_id is None: return 0
    digest = hashlib.sha256(organization_id.__str__().encode()).digest()
    return int.from_bytes(digest[:4], 'big') % workers


def session_id(worker: int, workers: int) -> bytes:
    # Its first byte names the worker; the filter reads it to deliver every later datagram there.
    identifier = bytearray(os.urandom(16))
    if workers > 1: identifier[0] = worker + workers * (identifier[0] % ((256 - worker + workers - 1) // workers))
    return bytes(identifier)


def worker_of(identifier: bytes, workers: int) -> int:
    return identifier[0] % workers if workers > 1 else 0


def steering(workers: int) -> list[tuple]:
    # Logins (hello and authentication) all go to worker 0; the rest by the identifier's first byte.
    # The header is magic (4), version (1), type (1) and identifier (16).
    offset = len(Protocol.magic) + 1
    load_byte, jump_equal, modulo = 0x30, 0x15, 0x94
    return_a, return_k = 0x16, 0x06
    return [(load_byte, 0, 0, offset),
            (jump_equal, 4, 0, Protocol.client_hello),
            (jump_equal, 3, 0, Protocol.authentication),
            (load_byte, 0, 0, offset + 1),
            (modulo, 0, 0, workers),
            (return_a, 0, 0, 0),
            (return_k, 0, 0, 0)]


def orphan_signal():
    # A worker whose parent dies, even killed, receives SIGTERM instead of serving alone.
    try: ctypes.CDLL(None, use_errno=True).prctl(1, 15, 0, 0, 0)
    except (OSError, AttributeError): pass


def attach(udp: socket.socket, program: list[tuple]):
    # struct sock_fprog points at the instructions: they must stay alive during the call.
    instructions = b''.join(struct.pack('HBBI', *instruction) for instruction in program)
    buffer = ctypes.create_string_buffer(instructions)
    fprog = struct.pack('HL', len(program), ctypes.addressof(buffer))
    udp.setsockopt(socket.SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, fprog)


def group(address: str, port: int, workers: int) -> list[socket.socket]:
    # Bound in order: the filter's answer is the position in this list.
    sockets = []
    for _ in range(workers):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        udp.bind((address, port))
        sockets.append(udp)
    attach(sockets[0], steering(workers))
    return sockets


class Mailboxes:
    # One datagram channel per worker, made before forking: no other program can write to them.
    def __init__(self, workers: int):
        self.pairs = [socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM) for _ in range(workers)]
        for reader, writer in self.pairs:
            writer.setblocking(False)
            for end in (reader, writer):
                end.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
                end.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)

    def inbox(self, worker: int) -> socket.socket:
        return self.pairs[worker][0]

    def send(self, worker: int, message: dict) -> bool:
        try: self.pairs[worker][1].send(pickle.dumps(message))
        except (BlockingIOError, OSError): return False
        return True

    def receive(self, worker: int, limit: int = 64) -> list[dict]:
        messages, inbox = [], self.inbox(worker)
        for _ in range(limit):
            try: messages.append(pickle.loads(inbox.recv(1 << 20, socket.MSG_DONTWAIT)))
            except (BlockingIOError, InterruptedError): break
        return messages
