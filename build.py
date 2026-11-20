"""Builds the client as one executable with PyInstaller.

    python build.py                          # wintun.dll downloaded on Windows
    python build.py --wintun C:\\wintun.dll  # no internet: that file, as it is

The same executable opens the window without arguments and runs the commands
with them (VPN register ..., VPN connect ...). On Windows it carries wintun.dll
inside. Without --wintun it is downloaded from wintun.net and its signature is
checked; with --wintun the given .dll (or wintun .zip) is used where it is.
Each system builds its own executable: Windows on Windows, macOS on macOS.
"""
import argparse
import hashlib
import platform
import struct
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WINTUN_VERSION = '0.14.1'
WINTUN_URL = f'https://www.wintun.net/builds/wintun-{WINTUN_VERSION}.zip'
# Folder inside the wintun zip and PE machine code, by the architecture Python reports.
ARCHITECTURES = {'amd64': ('amd64', 0x8664), 'x86_64': ('amd64', 0x8664), 'arm64': ('arm64', 0xAA64),
                 'aarch64': ('arm64', 0xAA64), 'x86': ('x86', 0x14C), 'i386': ('x86', 0x14C),
                 'i686': ('x86', 0x14C), 'arm': ('arm', 0x1C4)}
ENTRY, NAME = 'connection/__main__.py', 'VPN'
# PyInstaller's usual manifest plus consoleAllocationPolicy: on Windows 11 24H2 and later the
# console executable gets no console of its own when opened with a double click, and still
# prints, reads and returns its exit code inside a terminal. Older Windows ignore it; there
# the window hides the console it was given.
MANIFEST = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"></requestedExecutionLevel>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"></supportedOS>
      <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"></supportedOS>
      <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"></supportedOS>
      <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"></supportedOS>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"></supportedOS>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
      <consoleAllocationPolicy xmlns="http://schemas.microsoft.com/SMI/2024/WindowsSettings">detached</consoleAllocationPolicy>
    </windowsSettings>
  </application>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"></assemblyIdentity>
    </dependentAssembly>
  </dependency>
</assembly>
'''


class BuildError(Exception):
    pass


def architecture(machine: str = None) -> tuple:
    machine = (machine or platform.machine()).lower()
    if machine not in ARCHITECTURES: raise BuildError(f'Unknown architecture: {machine}')
    return ARCHITECTURES[machine]


def pe_machine(path: Path) -> int:
    # The architecture a Windows DLL was built for, from its PE header.
    data = path.read_bytes()[:4096]
    if data[:2] != b'MZ': raise BuildError(f'{path} is not a Windows DLL')
    offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[offset:offset + 4] != b'PE\0\0': raise BuildError(f'{path} is not a Windows DLL')
    return struct.unpack_from('<H', data, offset + 4)[0]


def from_zip(archive: Path, folder: str, destination: Path) -> Path:
    # wintun-X.zip holds wintun/bin/<architecture>/wintun.dll.
    member = f'wintun/bin/{folder}/wintun.dll'
    try:
        with zipfile.ZipFile(archive) as opened:
            destination.mkdir(parents=True, exist_ok=True)
            target = destination / 'wintun.dll'
            target.write_bytes(opened.read(member))
    except (zipfile.BadZipFile, KeyError) as error:
        raise BuildError(f'{archive} does not hold {member}: {error}')
    return target


def signed(path: Path) -> str:
    # Windows checks the Authenticode signature; the signer is shown to whoever builds.
    script = (f"$s = Get-AuthenticodeSignature -LiteralPath '{path}'; "
              "Write-Output $s.Status; Write-Output $s.SignerCertificate.Subject")
    result = subprocess.run(['powershell', '-NoProfile', '-Command', script], capture_output=True, text=True)
    status, _, subject = result.stdout.strip().partition('\n')
    if status.strip() != 'Valid': raise BuildError(f'{path} has no valid signature ({status.strip() or result.stderr.strip()})')
    return subject.strip()


def wintun(options, work: Path, download=urllib.request.urlretrieve, verify=signed) -> Path:
    folder, machine = architecture(options.architecture)
    if options.wintun:
        # The person's own file, where it is; nothing is downloaded.
        given = Path(options.wintun).expanduser().resolve()
        if not given.is_file(): raise BuildError(f'{given} does not exist')
        dll = from_zip(given, folder, work / 'wintun') if given.suffix.lower() == '.zip' else given
        print(f'Wintun: {dll}')
    else:
        archive = work / f'wintun-{WINTUN_VERSION}.zip'
        archive.parent.mkdir(parents=True, exist_ok=True)
        print(f'Wintun: downloading {WINTUN_URL}')
        try: download(WINTUN_URL, archive)
        except OSError as error: raise BuildError(f'Could not download Wintun ({error}); use --wintun PATH')
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if options.wintun_sha256 and digest != options.wintun_sha256.lower():
            raise BuildError(f'The download does not match --wintun-sha256 (it is {digest})')
        print(f'Wintun: SHA-256 {digest} (pin it with --wintun-sha256)')
        dll = from_zip(archive, folder, work / 'wintun')
        print(f'Wintun: signed by {verify(dll)}')
    if pe_machine(dll) != machine:
        raise BuildError(f'{dll} is not for {folder}: build on the same architecture as the DLL')
    return dll


def command(options, dll: Path = None) -> list:
    arguments = [str(ROOT / ENTRY), '--onefile', '--name', NAME, '--paths', str(ROOT), '--noconfirm',
                 '--distpath', str(ROOT / 'dist'), '--workpath', str(ROOT / 'build' / 'work'),
                 '--specpath', str(ROOT / 'build'), '--collect-submodules', 'connection']
    # Windows and Linux keep a console so commands print and return exit codes; the window
    # hides it when opened with a double click. macOS wants an app bundle for the window.
    if options.system == 'Darwin': arguments.append('--windowed')
    if options.system == 'Windows':
        manifest = ROOT / 'build' / f'{NAME}.manifest'
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(MANIFEST, encoding='utf-8')
        arguments += ['--manifest', str(manifest)]
    if dll: arguments += ['--add-binary', f'{dll}{";" if options.system == "Windows" else ":"}.']
    return arguments


def main(arguments: list = None, run=None) -> int:
    parser = argparse.ArgumentParser(description='Build the VPN client as one executable.')
    parser.add_argument('--wintun', metavar='PATH', help='wintun.dll or wintun .zip to use as it is, without internet')
    parser.add_argument('--wintun-sha256', metavar='HEX', help='expected SHA-256 of the downloaded wintun zip')
    parser.add_argument('--architecture', help=argparse.SUPPRESS)
    parser.add_argument('--system', default=platform.system(), help=argparse.SUPPRESS)
    options = parser.parse_args(arguments)
    try:
        dll = None
        if options.system == 'Windows': dll = wintun(options, ROOT / 'build')
        elif options.wintun: print('Wintun is only for Windows: ignored.')
        if run is None:
            try: import PyInstaller.__main__ as pyinstaller
            except ImportError: raise BuildError('PyInstaller is missing: pip install -r requirements-build.txt')
            run = pyinstaller.run
        run(command(options, dll))
    except BuildError as error:
        print(f'Error: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__': raise SystemExit(main())
