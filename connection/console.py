"""One executable for the window and the command line.

Windows gives each executable either a console or none. This one has a
console, so commands print, read passwords and return exit codes normally.
Opened with a double click, the window hides that console, and asks once for
administrator rights, which the network card needs. Other systems need neither.
"""
import os
import subprocess
import sys


def windows() -> bool:
    return os.name == 'nt'


def hide_own_console(kernel32=None, user32=None):
    # Only a console the executable created itself (a double click) is hidden; a terminal stays.
    if not windows(): return False
    import ctypes
    kernel32, user32 = kernel32 or ctypes.windll.kernel32, user32 or ctypes.windll.user32
    processes = (ctypes.c_uint32 * 2)()
    if kernel32.GetConsoleProcessList(processes, 2) != 1: return False
    window = kernel32.GetConsoleWindow()
    if window: user32.ShowWindow(window, 0)
    kernel32.FreeConsole()
    return True


def is_administrator(shell32=None) -> bool:
    if not windows(): return hasattr(os, 'geteuid') and os.geteuid() == 0
    import ctypes
    shell32 = shell32 or ctypes.windll.shell32
    try: return bool(shell32.IsUserAnAdmin())
    except OSError: return False


def elevate(arguments: list, shell32=None) -> bool:
    # The window asks Windows to run it again as administrator; declining keeps it as it is.
    if not windows() or is_administrator(shell32): return False
    import ctypes
    shell32 = shell32 or ctypes.windll.shell32
    frozen = getattr(sys, 'frozen', False)
    program = sys.executable
    parameters = arguments if frozen else ['-m', 'connection', *arguments]
    result = shell32.ShellExecuteW(None, 'runas', program, subprocess.list2cmdline(parameters), None, 1)
    # Above 32 means the elevated copy started: this one ends.
    return result > 32
