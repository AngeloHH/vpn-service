"""The virtual network card of the client, the same way on Linux, macOS and Windows.

Every device offers the same calls: fileno() for select, read() for one IP
packet, write(packet), configure(address, mask) for the primary address and
close(). Linux and macOS bring their TUN in the kernel; Windows uses Wintun
(wintun.dll), which travels inside the executable.
"""
import os
import platform
import socket
import struct
import subprocess
import sys
import threading
import uuid
from pathlib import Path

from connection.errors import VPNError

MAXIMUM = 65535


def run(command: list):
    try: subprocess.run(command, check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise VPNError('tunnel_failed', reason=f'{command[0]}: {error}') from None


def prefix(mask: str) -> int:
    return sum(bin(int(octet)).count('1') for octet in mask.split('.'))


class LinuxDevice:
    # /dev/net/tun directly: no extra package, and the card disappears with the process.
    TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x400454CA, 0x0001, 0x1000

    def __init__(self, name: str, mtu: int):
        import fcntl
        self.mtu = mtu
        try:
            self.descriptor = os.open('/dev/net/tun', os.O_RDWR)
            request = struct.pack('16sH', name.encode()[:15], self.IFF_TUN | self.IFF_NO_PI)
            self.name = fcntl.ioctl(self.descriptor, self.TUNSETIFF, request)[:16].rstrip(b'\0').decode()
        except OSError as error:
            raise VPNError('tunnel_failed', reason=str(error)) from None

    def fileno(self) -> int: return self.descriptor

    def read(self, size: int = MAXIMUM) -> bytes: return os.read(self.descriptor, MAXIMUM)

    def write(self, packet: bytes) -> int: return os.write(self.descriptor, packet)

    def configure(self, address: str, mask: str):
        # The primary address replaces any previous one.
        run(['ip', 'address', 'flush', 'dev', self.name])
        run(['ip', 'address', 'add', f'{address}/{prefix(mask)}', 'dev', self.name])
        run(['ip', 'link', 'set', 'dev', self.name, 'mtu', str(self.mtu), 'up'])

    def close(self):
        try: os.close(self.descriptor)
        except OSError: pass


class MacDevice:
    # The kernel's utun: macOS names it (utun0, utun1...) and prefixes each packet with its family.
    CTLIOCGINFO, UTUN_OPT_IFNAME, CONTROL = 0xC0644E03, 2, b'com.apple.net.utun_control'
    FAMILIES = {4: socket.AF_INET, 6: getattr(socket, 'AF_INET6', 30)}

    def __init__(self, name: str, mtu: int):
        import fcntl
        self.mtu = mtu
        try:
            self.socket = socket.socket(socket.AF_SYSTEM, socket.SOCK_DGRAM, socket.SYSPROTO_CONTROL)
            information = fcntl.ioctl(self.socket, self.CTLIOCGINFO, struct.pack('I96s', 0, self.CONTROL))
            control = struct.unpack('I96s', information)[0]
            # Unit 0 lets the kernel choose a free utun.
            self.socket.connect((control, 0))
            self.name = self.socket.getsockopt(socket.SYSPROTO_CONTROL, self.UTUN_OPT_IFNAME, 128)
            self.name = self.name.rstrip(b'\0').decode()
        except (OSError, AttributeError) as error:
            raise VPNError('tunnel_failed', reason=str(error)) from None

    def fileno(self) -> int: return self.socket.fileno()

    def read(self, size: int = MAXIMUM) -> bytes:
        return self.socket.recv(MAXIMUM + 4)[4:]

    def write(self, packet: bytes) -> int:
        family = self.FAMILIES.get(packet[0] >> 4 if packet else 4, socket.AF_INET)
        return self.socket.send(struct.pack('!I', family) + packet) - 4

    def configure(self, address: str, mask: str):
        # A point-to-point card: its own address on both ends.
        run(['ifconfig', self.name, 'inet', address, address, 'netmask', mask, 'mtu', str(self.mtu), 'up'])

    def close(self):
        self.socket.close()


def wintun_path() -> Path or None:
    # Inside the executable first; then beside it or this package, or where VPN_WINTUN points.
    places = [os.environ.get('VPN_WINTUN')]
    if getattr(sys, '_MEIPASS', None): places.append(Path(sys._MEIPASS) / 'wintun.dll')
    places += [Path(sys.executable).parent / 'wintun.dll', Path(__file__).parent / 'wintun.dll']
    return next((Path(place) for place in places if place and Path(place).is_file()), None)


class WindowsDevice:
    """Wintun: packets come from a ring the driver fills.

    Windows cannot select on the driver, so one reader thread per client moves
    each packet to a local socket pair; the tunnel loop selects on that socket
    like on any other system.
    """
    CAPACITY, NO_MORE_ITEMS, INFINITE = 0x400000, 259, 0xFFFFFFFF

    def __init__(self, name: str, mtu: int, dll=None):
        self.name, self.mtu = name, mtu
        self.dll = dll or self.load()
        self.adapter = self.session = None
        self.stopped = threading.Event()
        try:
            self.open()
        except OSError as error:
            raise VPNError('tunnel_failed', reason=str(error)) from None
        self.inside, self.outside = socket.socketpair()
        self.reader = threading.Thread(target=self.pump, name='wintun-reader', daemon=True)
        self.reader.start()

    @staticmethod
    def load():
        import ctypes
        path = wintun_path()
        if not path: raise VPNError('tun_missing')
        try: dll = ctypes.WinDLL(str(path), use_last_error=True)
        except OSError as error: raise VPNError('tunnel_failed', reason=str(error)) from None
        handle, dword, pointer = ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_ubyte)
        signatures = dict(
            WintunCreateAdapter=([ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p], handle),
            WintunCloseAdapter=([handle], None),
            WintunStartSession=([handle, dword], handle),
            WintunEndSession=([handle], None),
            WintunGetReadWaitEvent=([handle], handle),
            WintunReceivePacket=([handle, ctypes.POINTER(dword)], pointer),
            WintunReleaseReceivePacket=([handle, pointer], None),
            WintunAllocateSendPacket=([handle, dword], pointer),
            WintunSendPacket=([handle, pointer], None))
        for name, (arguments, result) in signatures.items():
            function = getattr(dll, name)
            function.argtypes, function.restype = arguments, result
        return dll

    def open(self):
        import ctypes
        # The same name always gets the same identifier: Windows keeps one card, not a new one each time.
        identifier = uuid.uuid5(uuid.NAMESPACE_URL, f'vpn-service:{self.name}')
        guid = ctypes.create_string_buffer(identifier.bytes_le, 16)
        self.adapter = self.dll.WintunCreateAdapter(self.name, 'VPN', guid)
        if not self.adapter: raise ctypes.WinError(ctypes.get_last_error())
        self.session = self.dll.WintunStartSession(self.adapter, self.CAPACITY)
        if not self.session:
            error = ctypes.WinError(ctypes.get_last_error())
            self.dll.WintunCloseAdapter(self.adapter)
            raise error
        self.event = self.dll.WintunGetReadWaitEvent(self.session)

    def receive(self) -> bytes or None:
        # One packet from the driver's ring, or None when it is empty.
        import ctypes
        size = ctypes.c_uint32()
        packet = self.dll.WintunReceivePacket(self.session, ctypes.byref(size))
        if not packet:
            error = ctypes.get_last_error()
            if error == self.NO_MORE_ITEMS: return None
            raise ctypes.WinError(error)
        data = ctypes.string_at(packet, size.value)
        self.dll.WintunReleaseReceivePacket(self.session, packet)
        return data

    def wait(self):
        import ctypes
        # Wakes up at least every half second so close() never waits long.
        ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_void_p(self.event), 500)

    def pump(self):
        try:
            while not self.stopped.is_set():
                packet = self.receive()
                if packet is None: self.wait()
                else: self.inside.sendall(struct.pack('!H', len(packet)) + packet)
        except OSError:
            if not self.stopped.is_set(): self.inside.close()

    def fileno(self) -> int: return self.outside.fileno()

    def exactly(self, size: int) -> bytes:
        data = b''
        while len(data) < size:
            chunk = self.outside.recv(size - len(data))
            if not chunk: raise VPNError('tunnel_failed', reason='The Wintun reader stopped')
            data += chunk
        return data

    def read(self, size: int = MAXIMUM) -> bytes:
        # Exactly one packet; the rest stays in the socket, so select keeps reporting it.
        return self.exactly(struct.unpack('!H', self.exactly(2))[0])

    def write(self, packet: bytes) -> int:
        import ctypes
        target = self.dll.WintunAllocateSendPacket(self.session, len(packet))
        # A full ring drops the packet, like a busy card; the connection recovers by itself.
        if not target: return 0
        ctypes.memmove(target, packet, len(packet))
        self.dll.WintunSendPacket(self.session, target)
        return len(packet)

    def configure(self, address: str, mask: str):
        name = f'name={self.name}'
        run(['netsh', 'interface', 'ipv4', 'set', 'address', name, 'static', address, mask])
        run(['netsh', 'interface', 'ipv4', 'set', 'subinterface', self.name, f'mtu={self.mtu}', 'store=active'])

    def close(self):
        self.stopped.set()
        self.reader.join(2)
        for side in (self.inside, self.outside): side.close()
        if self.session: self.dll.WintunEndSession(self.session)
        if self.adapter: self.dll.WintunCloseAdapter(self.adapter)
        self.session = self.adapter = None


def open_device(name: str, mtu: int):
    # The card of this system; the name may change (macOS chooses utunN).
    system = platform.system()
    if system == 'Linux': return LinuxDevice(name, mtu)
    if system == 'Darwin': return MacDevice(name, mtu)
    if system == 'Windows': return WindowsDevice(name, mtu)
    raise VPNError('tun_missing')
