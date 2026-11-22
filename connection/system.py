import hashlib
import platform
import subprocess

import psutil

from connection import PROJECT, __version__

# The model is stable for a project version and never names real hardware.
MODEL = hashlib.sha256(PROJECT.encode()).hexdigest()[:6].upper() + ' v' + __version__
WINDOWS_TEMPERATURE = ('(Get-CimInstance -Namespace root/wmi -ClassName '
                       'MSAcpi_ThermalZoneTemperature).CurrentTemperature')


def temperature():
    # Each system exposes sensors differently; None means unavailable.
    system = platform.system()
    if system in ('Linux', 'FreeBSD'):
        sensors = getattr(psutil, 'sensors_temperatures', dict)() or {}
        readings = [entry.current for entries in sensors.values()
                    for entry in entries if entry.current]
        return round(max(readings), 1) if readings else None
    if system != 'Windows': return None
    command = ['powershell', '-NoProfile', '-Command', WINDOWS_TEMPERATURE]
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    try: output = subprocess.run(command, capture_output=True, text=True,
                                 timeout=10, creationflags=flags).stdout
    except (OSError, subprocess.TimeoutExpired): return None
    # WMI reports tenths of a kelvin.
    readings = [int(value) / 10 - 273.15 for value in output.split() if value.isdigit()]
    return round(max(readings), 1) if readings else None


class ProcessMetrics:
    def __init__(self, root: int = None):
        # The whole server: with several workers, the parent and every worker it started.
        self.process, self.cores = psutil.Process(root), psutil.cpu_count() or 1
        self.tree = root is not None
        self.known = {}
        self.members()

    def members(self) -> list:
        # The first CPU sample of each process only starts its measurement window.
        processes = [self.process, *(self.process.children() if self.tree else [])]
        known = {}
        for process in processes:
            known[process.pid] = self.known.get(process.pid)
            if known[process.pid]: continue
            try: process.cpu_percent(None)
            except psutil.Error: continue
            known[process.pid] = process
        self.known = {pid: process for pid, process in known.items() if process}
        return list(self.known.values())

    def sample(self) -> dict:
        # CPU is normalized to the whole machine, so 100% means every core.
        cpu = memory = 0
        for process in self.members():
            try: cpu, memory = cpu + process.cpu_percent(None), memory + process.memory_info().rss
            except psutil.Error: continue
        total = psutil.virtual_memory().total
        return dict(cpu=round(cpu / self.cores, 1), memory=memory,
                    memory_percent=round(memory * 100 / total, 1),
                    temperature=temperature())
