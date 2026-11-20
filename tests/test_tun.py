import ctypes
import os
import shutil
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from connection import tun
from connection.errors import VPNError


def checksum(header: bytes) -> int:
    total = sum(struct.unpack('!10H', header))
    while total >> 16: total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def udp_packet(source: str, destination: str, port: int, payload: bytes) -> bytes:
    udp = struct.pack('!HHHH', 40000, port, 8 + len(payload), 0) + payload
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                         socket.inet_aton(source), socket.inet_aton(destination))
    return header[:10] + struct.pack('!H', checksum(header)) + header[12:] + udp


LINUX = (os.name == 'posix' and os.path.exists('/dev/net/tun') and hasattr(os, 'geteuid')
         and os.geteuid() == 0 and shutil.which('ip'))


@unittest.skipUnless(LINUX, 'needs root, /dev/net/tun and ip')
class LinuxDeviceTest(unittest.TestCase):
    def test_packets_cross_a_real_card_both_ways(self):
        device = tun.LinuxDevice('vpntest9', 1420)
        self.addCleanup(device.close)
        self.assertEqual(device.name, 'vpntest9')
        device.configure('10.77.9.1', '255.255.255.0')
        # The kernel sends a datagram for 10.77.9.2 into the card...
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(sender.close)
        sender.sendto(b'hacia fuera', ('10.77.9.2', 9999))
        while True:
            packet = device.read()
            if packet[0] >> 4 == 4 and packet[9] == 17: break
        self.assertEqual((socket.inet_ntoa(packet[16:20]), packet[28:]), ('10.77.9.2', b'hacia fuera'))
        # ...and what the card writes reaches a local socket.
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(receiver.close)
        receiver.bind(('10.77.9.1', 9998))
        receiver.settimeout(2)
        device.write(udp_packet('10.77.9.2', '10.77.9.1', 9998, b'hacia dentro'))
        self.assertEqual(receiver.recv(100), b'hacia dentro')
        # A second configuration replaces the address.
        device.configure('10.77.8.1', '255.255.255.0')
        shown = tun.subprocess.run(['ip', 'address', 'show', 'dev', 'vpntest9'], capture_output=True, text=True).stdout
        self.assertIn('10.77.8.1/24', shown)
        self.assertNotIn('10.77.9.1', shown)
        device.close()
        gone = tun.subprocess.run(['ip', 'link', 'show', 'vpntest9'], capture_output=True, text=True)
        self.assertNotEqual(gone.returncode, 0)


class MacDeviceTest(unittest.TestCase):
    def test_each_packet_carries_its_family_on_the_wire(self):
        device = object.__new__(tun.MacDevice)
        device.socket, kernel = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(kernel.close)
        self.addCleanup(device.socket.close)
        packet = udp_packet('10.0.0.2', '10.0.0.1', 80, b'x')
        self.assertEqual(device.write(packet), len(packet))
        self.assertEqual(kernel.recv(100), struct.pack('!I', socket.AF_INET) + packet)
        six = bytes([0x60]) + bytes(39)
        device.write(six)
        self.assertEqual(kernel.recv(100)[:4], struct.pack('!I', tun.MacDevice.FAMILIES[6]))
        kernel.send(struct.pack('!I', socket.AF_INET) + packet)
        self.assertEqual(device.read(), packet)


class FakeWintun:
    # The calls the device makes, recording what is sent.
    def __init__(self):
        self.sent, self.buffers, self.ended = [], [], []

    def WintunEndSession(self, session): self.ended.append(session)

    def WintunCloseAdapter(self, adapter): self.ended.append(adapter)

    def WintunAllocateSendPacket(self, session, size):
        buffer = (ctypes.c_ubyte * size)()
        self.buffers.append(buffer)
        return ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))

    def WintunSendPacket(self, session, packet):
        self.sent.append(bytes(self.buffers[-1]))


class WindowsDeviceTest(unittest.TestCase):
    def device(self, packets):
        device = object.__new__(tun.WindowsDevice)
        device.dll, device.session, device.adapter = FakeWintun(), 1, None
        device.stopped = threading.Event()
        device.inside, device.outside = socket.socketpair()
        device.outside.settimeout(2)
        queue = list(packets)
        device.receive = lambda: queue.pop(0) if queue else None
        device.wait = lambda: device.stopped.wait(0.01)
        device.reader = threading.Thread(target=device.pump, daemon=True)
        device.reader.start()
        self.addCleanup(device.close)
        return device

    def test_the_reader_thread_hands_over_whole_packets(self):
        packets = [b'a' * 1400, b'b', b'c' * 70]
        device = self.device(packets)
        self.assertEqual([device.read() for _ in packets], packets)

    def test_writes_go_into_the_driver_ring(self):
        device = self.device([])
        self.assertEqual(device.write(b'paquete'), 7)
        self.assertEqual(device.dll.sent, [b'paquete'])
        device.dll.WintunAllocateSendPacket = lambda session, size: None
        self.assertEqual(device.write(b'lleno'), 0)

    def test_closing_stops_the_reader(self):
        device = self.device([])
        device.adapter = 2
        device.close()
        self.assertFalse(device.reader.is_alive())
        self.assertEqual(device.dll.ended, [1, 2])
        # Closing twice does nothing more.
        device.close()
        self.assertEqual(device.dll.ended, [1, 2])

    def test_the_dll_is_found_inside_the_executable_first(self):
        with tempfile.TemporaryDirectory() as folder:
            inside, chosen = Path(folder) / 'wintun.dll', Path(folder) / 'other.dll'
            inside.write_bytes(b'MZ')
            chosen.write_bytes(b'MZ')
            with mock.patch.object(tun.sys, '_MEIPASS', folder, create=True), mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(tun.wintun_path(), inside)
            with mock.patch.dict(os.environ, {'VPN_WINTUN': str(chosen)}):
                self.assertEqual(tun.wintun_path(), chosen)
        with mock.patch.object(tun, 'wintun_path', return_value=None), self.assertRaises(VPNError) as raised:
            tun.WindowsDevice.load()
        self.assertEqual(raised.exception.code, 'tun_missing')


class OpenDeviceTest(unittest.TestCase):
    def test_each_system_gets_its_card(self):
        for system, name in (('Linux', 'LinuxDevice'), ('Darwin', 'MacDevice'), ('Windows', 'WindowsDevice')):
            with self.subTest(system=system), mock.patch.object(tun.platform, 'system', return_value=system), \
                    mock.patch.object(tun, name) as device:
                tun.open_device('vpn0', 1420)
            device.assert_called_once_with('vpn0', 1420)
        with mock.patch.object(tun.platform, 'system', return_value='Plan9'), self.assertRaises(VPNError) as raised:
            tun.open_device('vpn0', 1420)
        self.assertEqual(raised.exception.code, 'tun_missing')


if __name__ == '__main__': unittest.main()
