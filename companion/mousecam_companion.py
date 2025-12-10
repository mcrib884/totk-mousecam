import subprocess
import sys
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import struct
import threading
import queue
import time
from pathlib import Path

if sys.platform == 'win32':
    import ctypes
    from ctypes import wintypes
    import keyboard as keyboard_lib

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    PAGE_READWRITE = 0x04
    PAGE_EXECUTE_READWRITE = 0x40

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("PartitionId", wintypes.WORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD)
        ]
else:
    from pynput import keyboard as keyboard_lib

from pynput import mouse as pynput_mouse

class MemoryScanner:
    def __init__(self, magic_value=0x4D4F5553):
        self.magic = magic_value
        self.magic_bytes = struct.pack('<I', magic_value)

    def find_process(self, process_names):
        pass

    def scan(self, pid):
        pass

    def write(self, address, data):
        pass

class WindowsScanner(MemoryScanner):
    def __init__(self):
        super().__init__()
        self.handle = None
        self.pid = 0
        self._write_func = kernel32.WriteProcessMemory
        self._write_func.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self._write_func.restype = wintypes.BOOL
        self._written = ctypes.c_size_t(0)

    def find_process(self, process_names):
        TH32CS_SNAPPROCESS = 0x00000002
        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD),
                        ("cntUsage", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD),
                        ("th32DefaultHeapID", ctypes.c_void_p),
                        ("th32ModuleID", wintypes.DWORD),
                        ("cntThreads", wintypes.DWORD),
                        ("th32ParentProcessID", wintypes.DWORD),
                        ("pcPriClassBase", wintypes.LONG),
                        ("dwFlags", wintypes.DWORD),
                        ("szExeFile", ctypes.c_char * 260)]

        hSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        pe32 = PROCESSENTRY32()
        pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

        found_pid = None
        found_name = None

        if kernel32.Process32First(hSnap, ctypes.byref(pe32)):
            while True:
                exe = pe32.szExeFile.decode('ansi', errors='ignore')
                if exe in process_names:
                    found_pid = pe32.th32ProcessID
                    found_name = exe
                    break
                if not kernel32.Process32Next(hSnap, ctypes.byref(pe32)):
                    break
        kernel32.CloseHandle(hSnap)

        if found_pid:
            self.pid = found_pid
            self.handle = kernel32.OpenProcess(0x1F0FFF, False, self.pid)
            return found_name, found_pid
        return None, None

    def is_process_alive(self):
        if not self.handle or self.pid == 0:
            return False
        STILL_ACTIVE = 259
        exit_code = wintypes.DWORD()
        if kernel32.GetExitCodeProcess(self.handle, ctypes.byref(exit_code)):
            return exit_code.value == STILL_ACTIVE
        return False

    def reset(self):
        if self.handle:
            kernel32.CloseHandle(self.handle)
        self.handle = None
        self.pid = 0

    def scan(self, pid):
        if not self.handle: return None

        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        found_addresses = []

        MEM_IMAGE = 0x1000000
        MEM_MAPPED = 0x40000
        MEM_PRIVATE = 0x20000
        CHUNK_SIZE = 50 * 1024 * 1024
        MIN_REGION_SIZE = 1 * 1024 * 1024

        regions = []
        while kernel32.VirtualQueryEx(self.handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            is_target_type = (mbi.Type == MEM_MAPPED) or (mbi.Type == MEM_PRIVATE)
            is_target_perm = (mbi.State == MEM_COMMIT) and (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))

            if is_target_type and is_target_perm and mbi.RegionSize >= MIN_REGION_SIZE:
                priority = 0 if mbi.Type == MEM_MAPPED else 1
                regions.append((priority, address, mbi.RegionSize, mbi.Type))

            address += mbi.RegionSize

        regions.sort(key=lambda r: (r[0], -r[2]))

        for priority, region_addr, region_size, mem_type in regions:
            try:
                read_offset = 0
                while read_offset < region_size:
                    size_to_read = min(CHUNK_SIZE, region_size - read_offset)
                    buffer = ctypes.create_string_buffer(size_to_read)
                    bytes_read = ctypes.c_size_t(0)

                    if kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(region_addr + read_offset), buffer, size_to_read, ctypes.byref(bytes_read)):
                        raw = buffer.raw
                        idx = raw.find(self.magic_bytes)
                        if idx != -1:
                            if idx + 8 <= len(raw):
                                version = struct.unpack('<I', raw[idx+4:idx+8])[0]
                                if version == 1:
                                    real_addr = region_addr + read_offset + idx
                                    found_addresses.append(real_addr)
                                    return found_addresses
                    read_offset += CHUNK_SIZE
            except Exception:
                pass
        return found_addresses

    def write(self, address, data):
        if not self.handle: return False
        return self._write_func(self.handle, address, data, len(data), ctypes.byref(self._written))

class WindowsInjector:
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32

        self.kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        self.kernel32.OpenProcess.restype = ctypes.c_void_p

        self.kernel32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
        self.kernel32.VirtualAllocEx.restype = ctypes.c_void_p

        self.kernel32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        self.kernel32.WriteProcessMemory.restype = ctypes.c_int

        self.kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
        self.kernel32.GetModuleHandleW.restype = ctypes.c_void_p

        self.kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.kernel32.GetProcAddress.restype = ctypes.c_void_p

        self.kernel32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
        self.kernel32.CreateRemoteThread.restype = ctypes.c_void_p

        self.kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.kernel32.WaitForSingleObject.restype = ctypes.c_uint32

        self.kernel32.GetExitCodeThread.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        self.kernel32.GetExitCodeThread.restype = ctypes.c_int

    def inject(self, pid, dll_path):
        PROCESS_ALL_ACCESS = 0x1F0FFF
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_READWRITE = 0x04

        h_process = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            print(f"DEBUG: Failed to open process {pid}. Error: {self.kernel32.GetLastError()}")
            return False

        try:
            path_bytes = dll_path.encode('utf-8') + b'\0'
            path_len = len(path_bytes)

            h_process_ptr = ctypes.c_void_p(h_process)

            remote_mem = self.kernel32.VirtualAllocEx(h_process_ptr, None, path_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            if not remote_mem:
                print(f"DEBUG: VirtualAllocEx failed. Error: {self.kernel32.GetLastError()}")
                return False

            print(f"DEBUG: Remote memory allocated at: {hex(remote_mem)}")

            written = ctypes.c_size_t(0)
            remote_mem_ptr = ctypes.c_void_p(remote_mem)

            if not self.kernel32.WriteProcessMemory(h_process_ptr, remote_mem_ptr, path_bytes, path_len, ctypes.byref(written)):
                err = self.kernel32.GetLastError()
                print(f"DEBUG: WriteProcessMemory failed. Error Code: {err}")
                return False

            h_kernel32 = self.kernel32.GetModuleHandleW("kernel32.dll")
            load_lib = self.kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
            print(f"DEBUG: LoadLibraryA address: {hex(load_lib)}")

            thread_id = ctypes.c_ulong(0)
            h_thread = self.kernel32.CreateRemoteThread(h_process_ptr, None, 0, ctypes.c_void_p(load_lib), remote_mem_ptr, 0, ctypes.byref(thread_id))

            if not h_thread:
                err = self.kernel32.GetLastError()
                print(f"DEBUG: CreateRemoteThread failed. Error Code: {err}")
                return False

            print(f"DEBUG: Remote thread created. ID: {thread_id.value}")
            self.kernel32.WaitForSingleObject(h_thread, 5000)

            exit_code = ctypes.c_uint32(0)
            self.kernel32.GetExitCodeThread(h_thread, ctypes.byref(exit_code))
            print(f"DEBUG: Remote thread exit code: {hex(exit_code.value)}")

            self.kernel32.CloseHandle(h_thread)

            if exit_code.value == 0:
                 print("DEBUG: LoadLibraryA failed (Exit Code 0). DLL path check or dependencies missing.")
                 return False

            return True
        finally:
            self.kernel32.CloseHandle(h_process)

class PipeClient:
    STATUS_MAGIC = 0x53544154

    def __init__(self, pipe_name):
        self.pipe_name = pipe_name
        self.handle = None
        self.kernel32 = ctypes.windll.kernel32
        self.last_dll_status = ""
        self.last_status_code = 0
        self.last_target_count = 0

    def connect(self):
        try:
            GENERIC_READ = 0x80000000
            GENERIC_WRITE = 0x40000000
            OPEN_EXISTING = 3
            FILE_ATTRIBUTE_NORMAL = 128

            h_pipe = self.kernel32.CreateFileW(
                self.pipe_name,
                GENERIC_READ | GENERIC_WRITE,
                0,
                None,
                OPEN_EXISTING,
                0,
                None
            )

            if h_pipe == -1 or h_pipe == 0xFFFFFFFFFFFFFFFF:
                err = self.kernel32.GetLastError()
                if err != 2:
                    print(f"DEBUG: Pipe CreateFile failed. Error: {err}")
                return False

            self.handle = h_pipe
            return True
        except Exception as e:
            print(f"DEBUG: Pipe connect exception: {e}")
            return False

    def write(self, data):
        if not self.handle: return False
        try:
            written = ctypes.c_uint32(0)
            if not self.kernel32.WriteFile(self.handle, data, len(data), ctypes.byref(written), None):
                err = self.kernel32.GetLastError()
                print(f"DEBUG: WriteFile failed. Error: {err}")
                self.close()
                return False
            return True
        except Exception as e:
             print(f"DEBUG: WriteFile exception: {e}")
             self.handle = None
             return False

    def read_status(self):
        if not self.handle:
            return None
        try:
            bytes_available = ctypes.c_uint32(0)
            if not self.kernel32.PeekNamedPipe(self.handle, None, 0, None, ctypes.byref(bytes_available), None):
                return None

            if bytes_available.value == 0:
                return None

            STATUS_SIZE = 76
            if bytes_available.value >= STATUS_SIZE:
                buffer = ctypes.create_string_buffer(STATUS_SIZE)
                bytes_read = ctypes.c_uint32(0)

                if self.kernel32.ReadFile(self.handle, buffer, STATUS_SIZE, ctypes.byref(bytes_read), None):
                    if bytes_read.value == STATUS_SIZE:
                        data = buffer.raw
                        magic = struct.unpack('<I', data[0:4])[0]
                        if magic == self.STATUS_MAGIC:
                            status_code = struct.unpack('<I', data[4:8])[0]
                            target_count = struct.unpack('<I', data[8:12])[0]
                            message = data[12:76].split(b'\x00')[0].decode('utf-8', errors='ignore')

                            self.last_status_code = status_code
                            self.last_target_count = target_count
                            self.last_dll_status = message

                            return {
                                'code': status_code,
                                'targets': target_count,
                                'message': message
                            }
            return None
        except Exception as e:
            print(f"DEBUG: ReadStatus exception: {e}")
            return None

    def close(self):
        if self.handle:
            try:
                self.kernel32.CloseHandle(self.handle)
            except:
                pass
            self.handle = None

class LinuxScanner(MemoryScanner):
    def __init__(self):
        super().__init__()
        self.mem_file = None
        self.pid = 0

    def find_process(self, process_names):
        print(f"DEBUG: Looking for processes: {process_names}")

        candidates = []
        process_info = {}

        try:
            for pid_str in os.listdir('/proc'):
                if not pid_str.isdigit(): continue
                pid = int(pid_str)

                try:
                    info = {'pid': pid, 'ppid': 0, 'rss': 0, 'name': '', 'cmd': ''}

                    try:
                        with open(f'/proc/{pid}/status', 'r') as f:
                            for line in f:
                                if line.startswith('Name:'):
                                    info['name'] = line.split(maxsplit=1)[1].strip()
                                elif line.startswith('PPid:'):
                                    info['ppid'] = int(line.split()[1])
                                elif line.startswith('VmRSS:'):
                                    info['rss'] = int(line.split()[1])
                    except:
                        pass

                    try:
                        with open(f'/proc/{pid}/cmdline', 'r') as f:
                            info['cmd'] = f.read().replace('\0', ' ')
                    except:
                        pass

                    process_info[pid] = info

                    matched = False
                    for pname in process_names:
                        if info['name'] == pname:
                            matched = True
                        elif pname in info['cmd']:
                            matched = True

                    if matched:
                        print(f"DEBUG: Found candidate PID {pid} ({info['name']}) RSS={info['rss']}kB")
                        candidates.append(pid)

                except Exception:
                    continue
        except Exception as e:
            print(f"DEBUG: Error identifying processes: {e}")
            return None, None

        if not candidates:
            return None, None

        children_map = {}
        for pid, info in process_info.items():
            ppid = info.get('ppid', 0)
            if ppid not in children_map: children_map[ppid] = []
            children_map[ppid].append(pid)

        final_candidates = set(candidates)
        queue = list(candidates)

        while queue:
            parent = queue.pop(0)
            if parent in children_map:
                for child in children_map[parent]:
                    if child not in final_candidates:
                        final_candidates.add(child)
                        queue.append(child)
                        child_name = process_info.get(child, {}).get('name', 'Unknown')
                        child_rss = process_info.get(child, {}).get('rss', 0)
                        print(f"DEBUG: Adding descendant PID {child} ({child_name}) RSS={child_rss}kB")

        best_pid = 0
        max_rss = -1
        best_name = ""

        for pid in final_candidates:
            if pid not in process_info: continue
            rss = process_info[pid]['rss']
            if rss > max_rss:
                max_rss = rss
                best_pid = pid
                best_name = process_info[pid]['name']

        if best_pid:
            print(f"DEBUG: Selected PID {best_pid} ({best_name}) with {max_rss}kB RSS")
            self.pid = best_pid
            return best_name, best_pid

        return None, None

    def scan(self, pid):
        print(f"DEBUG: Starting scan for PID {pid}")
        maps_path = f'/proc/{pid}/maps'
        mem_path = f'/proc/{pid}/mem'
        found = []

        CHUNK_SIZE = 50 * 1024 * 1024
        MIN_REGION_SIZE = 1 * 1024 * 1024

        try:
            self.mem_file = open(mem_path, 'r+b', buffering=0)
            print("DEBUG: Opened process memory")

            regions = []
            with open(maps_path, 'r') as maps:
                for line in maps:
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    perms = parts[1]

                    if 'r' not in perms or 'w' not in perms:
                        continue

                    addr_range = parts[0].split('-')
                    start = int(addr_range[0], 16)
                    end = int(addr_range[1], 16)
                    size = end - start

                    if size < MIN_REGION_SIZE:
                        continue

                    path = parts[5] if len(parts) > 5 else ''
                    is_anon = (path == '' or path.startswith('['))
                    priority = 0 if is_anon else 1

                    regions.append((priority, -size, start, size))

            regions.sort()
            print(f"DEBUG: Scanning {len(regions)} candidate regions")

            for priority, neg_size, start, size in regions:
                try:
                    read_offset = 0
                    while read_offset < size:
                        size_to_read = min(CHUNK_SIZE, size - read_offset)
                        self.mem_file.seek(start + read_offset)
                        chunk = self.mem_file.read(size_to_read)

                        if not chunk:
                            break

                        idx = chunk.find(self.magic_bytes)
                        if idx != -1:
                            if idx + 8 <= len(chunk):
                                ver = struct.unpack('<I', chunk[idx+4:idx+8])[0]
                                if ver == 1:
                                    found_addr = start + read_offset + idx
                                    print(f"DEBUG: Found magic at {hex(found_addr)}")
                                    found.append(found_addr)
                                    return found

                        read_offset += CHUNK_SIZE

                except Exception:
                    continue

            print(f"DEBUG: Scan complete, found {len(found)} addresses")
        except Exception as e:
            print(f"Linux scan error: {e}")
            if isinstance(e, PermissionError):
                print("DEBUG: Permission denied! Try running with sudo.")

        return found

    def is_process_alive(self):
        if self.pid == 0:
            return False
        try:
            return os.path.exists(f'/proc/{self.pid}')
        except:
            return False

    def write(self, address, data):
        if not self.mem_file:
            print("DEBUG: Write failed - no mem_file handle", flush=True)
            return False
        try:
            self.mem_file.seek(address)
            self.mem_file.write(data)
            self.mem_file.flush()
            return True
        except Exception as e:
            print(f"DEBUG: Write exception at {hex(address)}: {e}", flush=True)
            return False

    def reset(self):
        if self.mem_file:
            try:
                self.mem_file.close()
            except:
                pass
        self.mem_file = None
        self.pid = 0
        self.pid = 0

DEFAULT_CONFIG = {
    "sd_card_path": "",
    "emulator_path": "",
    "target_ip": "127.0.0.1",
    "target_port": 5555,
    "sensitivity": 1.0,
    "invert_y": False,
    "toggle_hotkey": "F3",
    "mouse_bindings": {
        "left": "ZL",
        "right": "ZR",
        "middle": "None",
        "mouse4": "None",
        "mouse5": "None"
    }
}

GAMEPAD_BUTTONS = ["None", "A", "B", "X", "Y", "L", "R", "ZL", "ZR",
                   "Plus", "Minus", "DPadUp", "DPadDown", "DPadLeft", "DPadRight",
                   "StickL", "StickR"]

def get_config_path():
    if sys.platform == 'win32':
        base = os.environ.get('APPDATA', os.path.expanduser('~'))
    else:
        base = os.environ.get('XDG_CONFIG_HOME', os.path.expanduser('~/.config'))
    config_dir = Path(base) / 'mousecam'
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / 'config.json'

def load_config():
    path = get_config_path()
    if path.exists():
        try:
            with open(path, 'r') as f:
                loaded = json.load(f)
                config = DEFAULT_CONFIG.copy()
                config.update(loaded)
                if 'mouse_bindings' in loaded:
                    config['mouse_bindings'] = DEFAULT_CONFIG['mouse_bindings'].copy()
                    config['mouse_bindings'].update(loaded['mouse_bindings'])
                return config
        except:
            pass
    return DEFAULT_CONFIG.copy()

def save_config(config):
    try:
        with open(get_config_path(), 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"Save error: {e}")

BUTTON_FLAGS = {
    "A": 1 << 0, "B": 1 << 1, "X": 1 << 2, "Y": 1 << 3,
    "StickL": 1 << 4, "StickR": 1 << 5, "L": 1 << 6, "R": 1 << 7,
    "ZL": 1 << 8, "ZR": 1 << 9, "Plus": 1 << 10, "Minus": 1 << 11,
    "DPadLeft": 1 << 12, "DPadUp": 1 << 13, "DPadRight": 1 << 14, "DPadDown": 1 << 15,
}

class SharedMouseData:
    MAGIC = 0x4D4F5553
    VERSION = 1
    SIZE = 32

    def __init__(self):
        self.delta_x = 0.0
        self.delta_y = 0.0
        self.scroll_delta = 0.0
        self.buttons = 0
        self.sequence = 0
        self.enabled = 0
        self.raw_buttons = 0

    def pack(self):
        return struct.pack('<IIfffIIBBBB',
                          self.MAGIC, self.VERSION,
                          self.delta_x, self.delta_y, self.scroll_delta,
                          self.buttons, self.sequence,
                          self.enabled, self.raw_buttons, 0, 0)

class MouseCapture:
    def __init__(self):
        self.enabled = False
        self.delta_x = 0.0
        self.delta_y = 0.0
        self.scroll_delta = 0.0
        self.buttons = {}
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._use_raw_input = False
        self.emulator_process_name = None
        self._target_hwnd = None

        if sys.platform == 'win32':
            self._hwnd = None
            self._raw_input_registered = False
        else:
            self._mouse_fd = None
            self._cursor_lock_active = False
            self._cursor_lock_center = None
            self._cursor_lock_thread = None

    def start(self):
        self._running = True
        if sys.platform == 'win32':
            self._thread = threading.Thread(target=self._windows_raw_input_loop, daemon=True)
            self._thread.start()
        else:
            self._thread = threading.Thread(target=self._linux_raw_input_loop, daemon=True)
            self._thread.start()

        self._pynput_listener = pynput_mouse.Listener(
            on_click=self._on_click,
            on_scroll=self._on_scroll
        )
        self._pynput_listener.start()

    def stop(self):
        self._running = False
        if hasattr(self, '_pynput_listener'):
            self._pynput_listener.stop()

    def set_enabled(self, enabled):
        self.enabled = enabled
        with self._lock:
            self.delta_x = 0.0
            self.delta_y = 0.0
            self.scroll_delta = 0.0

        if sys.platform == 'win32':
            self._lock_cursor_windows(enabled)
        else:
            self._lock_cursor_linux(enabled)

    def get_and_reset_delta(self):
        with self._lock:
            dx, dy, scroll = self.delta_x, self.delta_y, self.scroll_delta
            self.delta_x = 0.0
            self.delta_y = 0.0
            self.scroll_delta = 0.0
            return dx, dy, scroll

    def get_buttons(self):
        with self._lock:
            return self.buttons.copy()

    def _on_click(self, x, y, button, pressed):
        btn_map = {
            pynput_mouse.Button.left: 'left',
            pynput_mouse.Button.right: 'right',
            pynput_mouse.Button.middle: 'middle',
        }
        try:
            btn_map[pynput_mouse.Button.x1] = 'x1'
            btn_map[pynput_mouse.Button.x2] = 'x2'
        except AttributeError:
            pass

        with self._lock:
            if button in btn_map:
                self.buttons[btn_map[button]] = pressed

    def _on_scroll(self, x, y, dx, dy):
        if self.enabled:
            with self._lock:
                val = 1.0 if dy > 0 else -1.0 if dy < 0 else 0.0
                self.scroll_delta += val

    def _windows_raw_input_loop(self):
        import ctypes
        from ctypes import wintypes, byref, sizeof, Structure, c_uint, c_ushort, c_short, c_long

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE

        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID
        ]
        user32.CreateWindowExW.restype = wintypes.HWND

        WM_INPUT = 0x00FF
        RIM_TYPEMOUSE = 0
        RIDEV_INPUTSINK = 0x00000100
        RID_INPUT = 0x10000003
        MOUSE_MOVE_ABSOLUTE = 0x01
        HID_USAGE_PAGE_GENERIC = 0x01
        HID_USAGE_GENERIC_MOUSE = 0x02

        class RAWINPUTDEVICE(Structure):
            _fields_ = [
                ("usUsagePage", c_ushort),
                ("usUsage", c_ushort),
                ("dwFlags", wintypes.DWORD),
                ("hwndTarget", wintypes.HWND),
            ]

        class RAWINPUTHEADER(Structure):
            _fields_ = [
                ("dwType", wintypes.DWORD),
                ("dwSize", wintypes.DWORD),
                ("hDevice", wintypes.HANDLE),
                ("wParam", wintypes.WPARAM),
            ]

        class RAWMOUSE_BUTTONS(Structure):
            _fields_ = [
                ("usButtonFlags", c_ushort),
                ("usButtonData", c_ushort)
            ]

        class RAWMOUSE_UNION(ctypes.Union):
            _fields_ = [
                ("ulButtons", wintypes.ULONG),
                ("buttons", RAWMOUSE_BUTTONS)
            ]

        class RAWMOUSE(Structure):
            _fields_ = [
                ("usFlags", c_ushort),
                ("pad", c_ushort),
                ("u", RAWMOUSE_UNION),
                ("ulRawButtons", wintypes.ULONG),
                ("lLastX", c_long),
                ("lLastY", c_long),
                ("ulExtraInformation", wintypes.ULONG),
            ]

        class RAWINPUT(Structure):
            _fields_ = [
                ("header", RAWINPUTHEADER),
                ("mouse", RAWMOUSE),
            ]

        LRESULT = ctypes.c_longlong
        WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.DefWindowProcW.restype = LRESULT

        def wnd_proc(hwnd, msg, wparam, lparam):
            if msg == WM_INPUT:
                size = wintypes.UINT(sizeof(RAWINPUT))
                raw = RAWINPUT()
                result = user32.GetRawInputData(lparam, RID_INPUT, byref(raw), byref(size), sizeof(RAWINPUTHEADER))
                if result > 0 and raw.header.dwType == RIM_TYPEMOUSE:
                    if self.enabled:
                        dx = raw.mouse.lLastX
                        dy = raw.mouse.lLastY
                        if not (raw.mouse.usFlags & MOUSE_MOVE_ABSOLUTE):
                            with self._lock:
                                self.delta_x += float(dx)
                                self.delta_y += float(dy)
                                if not hasattr(self, '_input_count'):
                                    self._input_count = 0
                                self._input_count += 1
                return 0
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wnd_proc = WNDPROC(wnd_proc)

        class WNDCLASS(Structure):
            _fields_ = [
                ("style", wintypes.UINT),
                ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON),
                ("hCursor", wintypes.HICON),
                ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR),
            ]

        wc = WNDCLASS()
        wc.lpfnWndProc = self._wnd_proc
        wc.hInstance = kernel32.GetModuleHandleW(None)
        wc.lpszClassName = "MouseCamRawInput"
        user32.RegisterClassW(byref(wc))

        self._hwnd = user32.CreateWindowExW(0, "MouseCamRawInput", "RawInput", 0, 0, 0, 1, 1, None, None, wc.hInstance, None)

        if not self._hwnd:
            self._start_pynput_fallback()
            return

        rid = RAWINPUTDEVICE()
        rid.usUsagePage = HID_USAGE_PAGE_GENERIC
        rid.usUsage = HID_USAGE_GENERIC_MOUSE
        rid.dwFlags = RIDEV_INPUTSINK
        rid.hwndTarget = self._hwnd

        if not user32.RegisterRawInputDevices(byref(rid), 1, sizeof(RAWINPUTDEVICE)):
            self._start_pynput_fallback()
            return

        self._use_raw_input = True

        msg = wintypes.MSG()
        raw = RAWINPUT()

        while self._running:
            if user32.PeekMessageW(byref(msg), self._hwnd, 0, 0, 1):
                if msg.message == WM_INPUT:
                    size = wintypes.UINT(sizeof(RAWINPUT))

                    if user32.GetRawInputData(msg.lParam, RID_INPUT, byref(raw), byref(size), sizeof(RAWINPUTHEADER)) > 0:
                        if raw.header.dwType == RIM_TYPEMOUSE:
                            if self.enabled:
                                mouse = raw.mouse
                                dx = mouse.lLastX
                                dy = mouse.lLastY
                                if not (mouse.usFlags & MOUSE_MOVE_ABSOLUTE):
                                    with self._lock:
                                        self.delta_x += float(dx)
                                        self.delta_y += float(dy)
                                        if not hasattr(self, '_input_count'): self._input_count = 0
                                        self._input_count += 1
                else:
                    user32.TranslateMessage(byref(msg))
                    user32.DispatchMessageW(byref(msg))
            else:
                time.sleep(0.001)

    def _linux_raw_input_loop(self):
        import struct
        import select

        if os.geteuid() != 0:
            print("WARNING: Not running as root! Input capture will likely fail.")
            print("Please run with: sudo python companion/mousecam_companion.py")

        mouse_path = '/dev/input/mice'

        print(f"DEBUG: Attempting to read from {mouse_path}", flush=True)

        try:
            self._mouse_fd = open(mouse_path, 'rb')
            self._use_raw_input = True
            print(f"DEBUG: Successfully opened {mouse_path}", flush=True)
        except PermissionError:
            print("DEBUG: Permission denied opening mouse device! (Are you root?)", flush=True)
            self._start_pynput_fallback()
            return
        except FileNotFoundError:
            print("DEBUG: Mouse device not found", flush=True)
            self._start_pynput_fallback()
            return
        except Exception as e:
            print(f"DEBUG: Error opening mouse: {e}", flush=True)
            self._start_pynput_fallback()
            return

        try:
            while self._running:
                r, w, x = select.select([self._mouse_fd], [], [], 1.0)
                if not r: continue

                data = self._mouse_fd.read(3)
                if len(data) == 3:
                    buttons, dx, dy = struct.unpack('Bbb', data)
                    if self.enabled:
                        with self._lock:
                            self.delta_x += float(dx)
                            self.delta_y += float(-dy)
                            self.buttons['left'] = bool(buttons & 0x01)
                            self.buttons['right'] = bool(buttons & 0x02)
                            self.buttons['middle'] = bool(buttons & 0x04)
        except Exception as e:
            print(f"DEBUG: Input loop error: {e}", flush=True)
        finally:
            if self._mouse_fd:
                try:
                    self._mouse_fd.close()
                except:
                    pass

    def _start_pynput_fallback(self):
        self._last_x = None
        self._last_y = None

        def on_move(x, y):
            if not self.enabled:
                self._last_x = None
                self._last_y = None
                return
            with self._lock:
                if self._last_x is not None:
                    self.delta_x += (x - self._last_x)
                    self.delta_y += (y - self._last_y)
                self._last_x = x
                self._last_y = y

        print("DEBUG: Starting pynput fallback listener...")
        listener = pynput_mouse.Listener(on_move=on_move)
        listener.start()

    def _find_window_by_process(self, process_name):
        if sys.platform != 'win32':
            return None

        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        EnumWindowsProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        found_hwnd = [None]
        target_name = process_name.lower()

        def enum_callback(hwnd, lparam):
            if not user32.IsWindowVisible(hwnd):
                return True
            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            hProcess = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
            if hProcess:
                try:
                    exe_path = ctypes.create_unicode_buffer(260)
                    size = wintypes.DWORD(260)
                    if kernel32.QueryFullProcessImageNameW(hProcess, 0, exe_path, ctypes.byref(size)):
                        exe_name = os.path.basename(exe_path.value).lower()
                        if exe_name == target_name:
                            title_len = user32.GetWindowTextLengthW(hwnd)
                            if title_len > 0:
                                found_hwnd[0] = hwnd
                                return False
                finally:
                    kernel32.CloseHandle(hProcess)
            return True

        user32.EnumWindows(EnumWindowsProc(enum_callback), 0)
        return found_hwnd[0]

    def _lock_cursor_windows(self, locked):
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32

        if locked:
            if self.emulator_process_name:
                self._target_hwnd = self._find_window_by_process(self.emulator_process_name)

            if self._target_hwnd:
                foreground = user32.GetForegroundWindow()
                if foreground != self._target_hwnd:
                    return

                if not hasattr(self, '_blank_cursor') or not self._blank_cursor:
                    and_mask = (ctypes.c_ubyte * 128)(*([0xFF] * 128))
                    xor_mask = (ctypes.c_ubyte * 128)(*([0x00] * 128))
                    self._blank_cursor = user32.CreateCursor(None, 0, 0, 32, 32, and_mask, xor_mask)

                self._cursor_lock_active = True
                if not hasattr(self, '_cursor_thread') or not self._cursor_thread.is_alive():
                    self._cursor_thread = threading.Thread(target=self._cursor_enforcement_loop, daemon=True)
                    self._cursor_thread.start()
        else:
            self._cursor_lock_active = False
            user32.ClipCursor(None)
            SPI_SETCURSORS = 0x0057
            user32.SystemParametersInfoW(SPI_SETCURSORS, 0, None, 0)
            self._target_hwnd = None

    def _cursor_enforcement_loop(self):
        import ctypes

        user32 = ctypes.windll.user32
        sw, sh = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
        cx, cy = sw // 2, sh // 2

        class RECT(ctypes.Structure):
            _fields_ = [("l", ctypes.c_long), ("t", ctypes.c_long),
                       ("r", ctypes.c_long), ("b", ctypes.c_long)]

        rect = RECT(cx - 1, cy - 1, cx + 1, cy + 1)

        OCR_CURSORS = [32512, 32513, 32514, 32515, 32516, 32642, 32643, 32644, 32645, 32646, 32648, 32649, 32650]

        while getattr(self, '_cursor_lock_active', False):
            try:
                user32.ClipCursor(ctypes.byref(rect))
                user32.SetCursorPos(cx, cy)
                if hasattr(self, '_blank_cursor') and self._blank_cursor:
                    user32.SetCursor(self._blank_cursor)
                    for cursor_id in OCR_CURSORS:
                        cursor_copy = user32.CopyIcon(self._blank_cursor)
                        if cursor_copy:
                            user32.SetSystemCursor(cursor_copy, cursor_id)
                time.sleep(0.05)
            except Exception:
                break

    def _lock_cursor_linux(self, locked):
        from pynput.mouse import Controller as MouseController
        import subprocess
        import ctypes

        if locked:
            self._cursor_lock_active = True
            self._cursor_lock_center = None
            self._emu_window_id = None
            self._cursor_hidden = False

            try:
                import tkinter as tk
                temp_root = tk.Tk()
                temp_root.withdraw()
                screen_width = temp_root.winfo_screenwidth()
                screen_height = temp_root.winfo_screenheight()
                temp_root.destroy()
                self._cursor_lock_center = (screen_width // 2, screen_height // 2)
            except:
                self._cursor_lock_center = (960, 540)

            try:
                search_patterns = []
                if self.emulator_process_name:
                    base = self.emulator_process_name.replace('.exe', '').replace('.appimage', '').replace('.AppImage', '')
                    search_patterns.append(base)
                search_patterns.extend(['citron', 'yuzu', 'Ryujinx', 'Tears of the Kingdom', 'Citron'])

                for pattern in search_patterns:
                    try:
                        result = subprocess.run(
                            ['xdotool', 'search', '--name', pattern],
                            capture_output=True, text=True, timeout=2
                        )
                        window_ids = result.stdout.strip().split('\n')
                        if window_ids and window_ids[0]:
                            self._emu_window_id = window_ids[0]
                            print(f"DEBUG: Found window '{pattern}' ID: {self._emu_window_id}", flush=True)
                            break
                    except:
                        continue
            except Exception as e:
                print(f"DEBUG: Window search failed: {e}", flush=True)

            xlib = None
            display = None
            blank_cursor = None
            root_window = None

            try:
                xlib = ctypes.CDLL('libX11.so.6')

                xlib.XOpenDisplay.argtypes = [ctypes.c_char_p]
                xlib.XOpenDisplay.restype = ctypes.c_void_p

                xlib.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
                xlib.XDefaultRootWindow.restype = ctypes.c_ulong

                xlib.XCreatePixmap.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
                xlib.XCreatePixmap.restype = ctypes.c_ulong

                xlib.XFreePixmap.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
                xlib.XFreePixmap.restype = ctypes.c_int

                xlib.XCreatePixmapCursor.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
                                                     ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint]
                xlib.XCreatePixmapCursor.restype = ctypes.c_ulong

                xlib.XDefineCursor.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
                xlib.XDefineCursor.restype = ctypes.c_int

                xlib.XUndefineCursor.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
                xlib.XUndefineCursor.restype = ctypes.c_int

                xlib.XFreeCursor.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
                xlib.XFreeCursor.restype = ctypes.c_int

                xlib.XFlush.argtypes = [ctypes.c_void_p]
                xlib.XFlush.restype = ctypes.c_int

                xlib.XCloseDisplay.argtypes = [ctypes.c_void_p]
                xlib.XCloseDisplay.restype = ctypes.c_int

                display = xlib.XOpenDisplay(None)
                if display:
                    root_window = xlib.XDefaultRootWindow(display)
                    pixmap = xlib.XCreatePixmap(display, root_window, 1, 1, 1)

                    class XColor(ctypes.Structure):
                        _fields_ = [
                            ('pixel', ctypes.c_ulong),
                            ('red', ctypes.c_ushort),
                            ('green', ctypes.c_ushort),
                            ('blue', ctypes.c_ushort),
                            ('flags', ctypes.c_char),
                            ('pad', ctypes.c_char),
                        ]

                    color = XColor()
                    color.pixel = 0
                    color.red = color.green = color.blue = 0

                    blank_cursor = xlib.XCreatePixmapCursor(display, pixmap, pixmap,
                                                            ctypes.byref(color), ctypes.byref(color), 0, 0)
                    xlib.XFreePixmap(display, pixmap)
                    print("DEBUG: X11 blank cursor created", flush=True)
                else:
                    print("DEBUG: Failed to open X display", flush=True)
                    xlib = None
            except Exception as e:
                print(f"DEBUG: Failed to initialize Xlib: {e}", flush=True)
                xlib = None

            def lock_loop():
                nonlocal xlib, display, blank_cursor, root_window
                mouse = MouseController()
                cx, cy = self._cursor_lock_center
                was_focused = False
                target_window = None

                if self._emu_window_id and xlib and display:
                    try:
                        target_window = int(self._emu_window_id)
                        print(f"DEBUG: Target window for cursor hiding: {target_window}", flush=True)
                    except:
                        target_window = root_window
                else:
                    target_window = root_window

                while self._cursor_lock_active:
                    try:
                        is_focused = False
                        if self._emu_window_id:
                            try:
                                result = subprocess.run(
                                    ['xdotool', 'getactivewindow'],
                                    capture_output=True, text=True, timeout=1
                                )
                                active_id = result.stdout.strip()
                                is_focused = (active_id == self._emu_window_id)
                            except:
                                is_focused = False
                        else:
                            is_focused = True

                        if is_focused:
                            mouse.position = (cx, cy)
                            if not was_focused and xlib and display and blank_cursor:
                                try:
                                    xlib.XDefineCursor(display, target_window, blank_cursor)
                                    xlib.XFlush(display)
                                    self._cursor_hidden = True
                                    print("DEBUG: X11 cursor hidden on target window", flush=True)
                                except Exception as e:
                                    print(f"DEBUG: XDefineCursor failed: {e}", flush=True)
                        else:
                            if was_focused and xlib and display and self._cursor_hidden:
                                try:
                                    xlib.XUndefineCursor(display, target_window)
                                    xlib.XFlush(display)
                                    self._cursor_hidden = False
                                    print("DEBUG: X11 cursor restored", flush=True)
                                except:
                                    pass

                        was_focused = is_focused
                        time.sleep(0.016)

                    except:
                        break

                if xlib and display:
                    try:
                        if self._cursor_hidden:
                            xlib.XUndefineCursor(display, target_window)
                        if blank_cursor:
                            xlib.XFreeCursor(display, blank_cursor)
                        xlib.XCloseDisplay(display)
                    except:
                        pass

            self._cursor_lock_thread = threading.Thread(target=lock_loop, daemon=True)
            self._cursor_lock_thread.start()

        else:
            self._cursor_lock_active = False

class MouseCamApp:
    def __init__(self):
        self.config = load_config()
        self.capture = MouseCapture()
        self.enabled = False
        self.sequence = 0
        self._running = False
        self.msg_queue = queue.Queue()
        self._build_ui()
        self._register_hotkey()
        self._start()

    def _build_ui(self):
        self.root = tk.Tk()
        self.root.title("MouseCam Companion")
        self.root.geometry("340x540")
        self.root.resizable(True, True)

        style = ttk.Style()
        style.configure('Big.TLabel', font=('Segoe UI', 16, 'bold'))

        main = ttk.Frame(self.root, padding="10")
        main.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(main)
        scrollbar = ttk.Scrollbar(main, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        parent = scrollable_frame

        status_frame = ttk.LabelFrame(parent, text="Status", padding="10")
        status_frame.pack(fill=tk.X, pady=(0, 10))

        self.status_label = ttk.Label(status_frame, text="DISABLED", style='Big.TLabel', foreground='red')
        self.status_label.pack()

        hotkey_row = ttk.Frame(status_frame)
        hotkey_row.pack(fill=tk.X, pady=2)
        ttk.Label(hotkey_row, text="Toggle Hotkey:").pack(side=tk.LEFT)
        self.hotkey_var = tk.StringVar(value=self.config.get('toggle_hotkey', 'F3'))
        self.hotkey_var.trace_add('write', lambda *_: self._on_hotkey_change())
        hotkey_combo = ttk.Combobox(hotkey_row, textvariable=self.hotkey_var,
                                    values=['F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12'],
                                    state='readonly', width=5)
        hotkey_combo.pack(side=tk.LEFT, padx=5)
        self.hotkey_hint = ttk.Label(status_frame, text=f"Press {self.hotkey_var.get()} to toggle")
        self.hotkey_hint.pack()
        self.ipc_label = ttk.Label(status_frame, text="", foreground='orange', wraplength=400)
        self.ipc_label.pack()

        if sys.platform == 'win32':
            self.dll_status_label = ttk.Label(status_frame, text="DLL: Waiting...", foreground='gray', wraplength=300)
            self.dll_status_label.pack(pady=(5, 0))


        emu_frame = ttk.LabelFrame(parent, text="Emulator Executable", padding="10")
        emu_frame.pack(fill=tk.X, pady=(0, 10))

        emu_row = ttk.Frame(emu_frame)
        emu_row.pack(fill=tk.X)

        self.emu_var = tk.StringVar(value=self.config.get('emulator_path', ''))
        self.emu_var.trace_add('write', lambda *_: self._auto_save())

        self.emu_entry = ttk.Entry(emu_row, textvariable=self.emu_var)
        self.emu_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Button(emu_row, text="Launch", command=self._launch_emu).pack(side=tk.RIGHT, padx=(5,0))
        ttk.Button(emu_row, text="Browse...", command=self._browse_emu).pack(side=tk.RIGHT, padx=(5,0))

        settings_frame = ttk.LabelFrame(parent, text="Settings", padding="10")
        settings_frame.pack(fill=tk.X, pady=(0, 10))

        sens_row = ttk.Frame(settings_frame)
        sens_row.pack(fill=tk.X, pady=2)
        ttk.Label(sens_row, text="Sensitivity:").pack(side=tk.LEFT)
        self.sens_var = tk.DoubleVar(value=self.config['sensitivity'])
        self.sens_var.trace_add('write', lambda *_: self._auto_save())
        ttk.Scale(sens_row, from_=0.1, to=3.0, variable=self.sens_var, orient=tk.HORIZONTAL, length=180).pack(side=tk.LEFT, padx=5)
        self.sens_label = ttk.Label(sens_row, text=f"{self.sens_var.get():.1f}")
        self.sens_label.pack(side=tk.LEFT)

        self.invert_var = tk.BooleanVar(value=self.config['invert_y'])
        self.invert_var.trace_add('write', lambda *_: self._auto_save())
        ttk.Checkbutton(settings_frame, text="Invert Y", variable=self.invert_var).pack(anchor=tk.W)

        bind_frame = ttk.LabelFrame(parent, text="Mouse → Gamepad", padding="10")
        bind_frame.pack(fill=tk.X)

        tools_frame = ttk.Frame(parent)
        tools_frame.pack(fill=tk.X, pady=10)

        btn_text = "Inject & Connect" if sys.platform == 'win32' else "Scan Memory"
        self.scan_btn = ttk.Button(tools_frame, text=btn_text, command=self._request_scan)
        self.scan_btn.pack(side=tk.LEFT)
        self.info_label = ttk.Label(tools_frame, text="v1.0", foreground="gray")
        self.info_label.pack(side=tk.RIGHT)

        self.binding_vars = {}
        for btn, label in [('left', 'Left Click'), ('right', 'Right Click'), ('mouse4', 'Mouse4'), ('mouse5', 'Mouse5')]:
            row = ttk.Frame(bind_frame)
            row.pack(fill=tk.X, pady=1)
            ttk.Label(row, text=f"{label}:", width=12).pack(side=tk.LEFT)
            var = tk.StringVar(value=self.config['mouse_bindings'].get(btn, 'None'))
            var.trace_add('write', lambda *_, b=btn: self._auto_save())
            self.binding_vars[btn] = var
            ttk.Combobox(row, textvariable=var, values=GAMEPAD_BUTTONS, state='readonly', width=8).pack(side=tk.LEFT)

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _browse_emu(self):
        if sys.platform == 'win32':
            filetypes = [("Executables", "*.exe"), ("All files", "*.*")]
        else:
            filetypes = [("All files", "*.*")]
        path = filedialog.askopenfilename(initialdir=str(Path(self.emu_var.get()).parent) if self.emu_var.get() else "/",
                                          title="Select Emulator Executable", filetypes=filetypes)
        if path:
            self.emu_var.set(path)

    def _launch_emu(self):
        path = self.emu_var.get()
        if not path or not Path(path).exists():
            self.status_label.configure(text="Emulator not found!", foreground='orange')
            return
        try:
            import subprocess
            cwd = str(Path(path).parent)
            subprocess.Popen([path], cwd=cwd)
            self.status_label.configure(text="Emulator Launched!", foreground='green')
        except Exception as e:
            self.status_label.configure(text=f"Error: {e}", foreground='red')

    def _auto_save(self):
        self.config['emulator_path'] = self.emu_var.get()
        self.config['sensitivity'] = self.sens_var.get()
        self.config['invert_y'] = self.invert_var.get()
        for btn, var in self.binding_vars.items():
            self.config['mouse_bindings'][btn] = var.get()
        save_config(self.config)
        self.sens_label.configure(text=f"{self.sens_var.get():.1f}")

    def _register_hotkey(self):
        hotkey = self.config.get('toggle_hotkey', 'F3').lower()
        self._current_hotkey = hotkey

        if sys.platform == 'win32':
            keyboard_lib.add_hotkey(hotkey, lambda: self.msg_queue.put('TOGGLE'))
        else:
            key_map = {
                'f1': keyboard_lib.Key.f1, 'f2': keyboard_lib.Key.f2, 'f3': keyboard_lib.Key.f3,
                'f4': keyboard_lib.Key.f4, 'f5': keyboard_lib.Key.f5, 'f6': keyboard_lib.Key.f6,
                'f7': keyboard_lib.Key.f7, 'f8': keyboard_lib.Key.f8, 'f9': keyboard_lib.Key.f9,
                'f10': keyboard_lib.Key.f10, 'f11': keyboard_lib.Key.f11, 'f12': keyboard_lib.Key.f12,
            }
            target_key = key_map.get(hotkey, keyboard_lib.Key.f3)

            def on_press(key):
                if key == target_key:
                    print("DEBUG: Hotkey pressed! (Queueing)")
                    self.msg_queue.put('TOGGLE')
            try:
                print("DEBUG: Starting keyboard listener...")
                listener = keyboard_lib.Listener(on_press=on_press)
                listener.start()
                print("DEBUG: Keyboard listener started")
            except Exception as e:
                print(f"DEBUG: Failed to start keyboard listener: {e}")

    def _on_hotkey_change(self):
        new_key = self.hotkey_var.get()
        self.config['toggle_hotkey'] = new_key
        save_config(self.config)
        self.hotkey_hint.configure(text=f"Press {new_key} to toggle")
        if sys.platform == 'win32':
            try:
                keyboard_lib.remove_hotkey(self._current_hotkey)
            except:
                pass
            keyboard_lib.add_hotkey(new_key.lower(), lambda: self.msg_queue.put('TOGGLE'))
            self._current_hotkey = new_key.lower()

    def _toggle(self):
        print("DEBUG: _toggle called")
        self.enabled = not self.enabled
        print(f"DEBUG: Toggling enabled to {self.enabled}")
        self.capture.set_enabled(self.enabled)
        if self.enabled:
            self.status_label.configure(text="ACTIVE", foreground='green')
        else:
            self.status_label.configure(text="DISABLED", foreground='red')
        print("DEBUG: _toggle finished")

    def _request_scan(self):
        self._mem_connected = False
        self._mem_address = None
        self._scan_requested = True
        self._mem_status = "Scan pending..."

    def _update_ui(self):
        if self._running:
            if self.enabled:
                self.status_label.config(text="ACTIVE (Capturing)", foreground='green')
            else:
                self.status_label.config(text="DISABLED", foreground='red')

            status = getattr(self, '_mem_status', 'Initializing...')
            connected = getattr(self, '_mem_connected', False)

            if connected:
                self.ipc_label.configure(text=f"✓ {status}", foreground='green')
            else:
                self.ipc_label.configure(text=f"⏳ {status}", foreground='orange')

            if sys.platform == 'win32' and hasattr(self, 'dll_status_label'):
                dll_status = getattr(self, '_dll_status', 'DLL: Waiting...')
                dll_code = getattr(self, '_dll_status_code', 0)

                if dll_code == 1:
                    color = 'orange'
                elif dll_code == 2:
                    color = 'blue'
                elif dll_code == 3:
                    color = 'green'
                elif dll_code == 4:
                    color = 'red'
                else:
                    color = 'gray'

                self.dll_status_label.configure(text=f"DLL: {dll_status}", foreground=color)

            self.root.after(100, self._update_ui)

    def _on_close(self):
        self._running = False
        self.capture.stop()
        if sys.platform == 'win32':
            keyboard_lib.unhook_all()
        self.root.destroy()

    def _check_queue(self):
        if self._running:
            try:
                while True:
                    msg = self.msg_queue.get_nowait()
                    if msg == 'TOGGLE':
                        print("DEBUG: Processing TOGGLE from queue")
                        self._toggle()
            except queue.Empty:
                pass
            finally:
                self.root.after(50, self._check_queue)

    def _start(self):
        self._running = True
        self.capture.start()
        self._write_thread = threading.Thread(target=self._write_loop, daemon=True)
        self._write_thread.start()
        self._check_queue()
        self._update_ui()

    def _write_loop(self):
        packet = SharedMouseData()

        if sys.platform == 'win32':
            scanner = WindowsScanner()
            injector = WindowsInjector()
            pipe_client = PipeClient(r'\\.\pipe\totk_mousecam')

            dll_name = "MouseCamInjector.dll"
            if getattr(sys, 'frozen', False):
                if hasattr(sys, '_MEIPASS'):
                    base_path = sys._MEIPASS
                else:
                    base_path = os.path.dirname(sys.executable)
            else:
                base_path = os.path.dirname(os.path.abspath(__file__))

            dll_path = os.path.join(base_path, dll_name)
            if not os.path.exists(dll_path):
                dll_path = os.path.join(base_path, 'injector', dll_name)

            if not os.path.exists(dll_path):
                dll_path = os.path.join(os.path.dirname(base_path), dll_name)

            if not os.path.exists(dll_path):
                print(f"WARNING: {dll_name} not found at {dll_path}")
        else:
            scanner = LinuxScanner()

        self._mem_connected = False
        self._mem_status = "Waiting for Process..."
        self._scan_requested = False

        target_process_names = ["Ryujinx.exe", "Ryujinx", "yuzu.exe", "yuzu", "suyu.exe", "suyu"]

        while self._running:
            try:
                config_emu_path = self.config.get('emulator_path', '')
                if config_emu_path:
                    emu_exe = os.path.basename(config_emu_path)
                    if emu_exe:
                         target_process_names = [emu_exe]

                if sys.platform == 'win32':
                    process_name, pid = scanner.find_process(target_process_names)
                else:
                    process_name, pid = scanner.find_process(target_process_names)

                if not pid:
                    self._mem_connected = False
                    self._mem_status = "Waiting for Emulator..."
                    self._update_ui()
                    time.sleep(1)
                    continue

                self._mem_status = f"Found {process_name} ({pid})"
                self._update_ui()

                if sys.platform == 'win32':
                     if pipe_client.connect():
                         self._mem_connected = True
                         self._mem_status = "Connected (Internal)"
                         self.capture.emulator_process_name = process_name

                         for _ in range(20):
                             status = pipe_client.read_status()
                             if status:
                                 self._dll_status = status['message']
                                 self._dll_status_code = status['code']
                                 print(f"DEBUG: Got DLL status: {status['message']}")
                                 break
                             time.sleep(0.1)

                         self._update_ui()
                     else:
                         if self._scan_requested:
                             self._mem_status = "Injecting DLL..."
                             self._dll_status = "Injecting..."
                             self._dll_status_code = 1
                             self._update_ui()

                             if not os.path.exists(dll_path):
                                 self._mem_status = "Error: DLL Not Found"
                                 self._scan_requested = False
                                 time.sleep(2)
                                 continue

                             if injector.inject(pid, dll_path):
                                 time.sleep(0.5)
                                 if pipe_client.connect():
                                     self._mem_connected = True
                                     self._mem_status = "Connected (Internal)"
                                     self.capture.emulator_process_name = process_name

                                     self._dll_status = "Scanning..."
                                     self._dll_status_code = 1
                                     self._update_ui()

                                     for _ in range(50):
                                         status = pipe_client.read_status()
                                         if status:
                                             self._dll_status = status['message']
                                             self._dll_status_code = status['code']
                                             print(f"DEBUG: Got DLL status: {status['message']}")
                                         time.sleep(0.1)
                                 else:
                                     self._mem_status = "Injection Success, Pipe Fail"
                             else:
                                 self._mem_status = "Injection Failed"

                             self._scan_requested = False
                             self._update_ui()
                else:
                    if self._scan_requested:
                        self._mem_status = "Scanning..."
                        self._update_ui()

                        addrs = scanner.scan(pid)
                        if addrs:
                            self._target_addresses = addrs
                            self._mem_connected = True
                            self._mem_status = f"Connected ({len(addrs)} addrs)"
                            self.capture.emulator_process_name = process_name
                        else:
                            self._mem_status = "Scan Failed - Not Found"

                        self._scan_requested = False
                        self._update_ui()

                while self._mem_connected:
                    if sys.platform == 'win32':
                        if not pipe_client.handle:
                            self._mem_connected = False; break
                        if not scanner.is_process_alive():
                            self._mem_connected = False; pipe_client.close(); break
                    else:
                        if not scanner.is_process_alive():
                            self._mem_connected = False; break

                    try:
                        dx, dy, scroll = self.capture.get_and_reset_delta()


                        dx_scaled = float(dx) * (self.config['sensitivity'] * 0.5)
                        dy_scaled = float(dy) * (self.config['sensitivity'] * 0.5)
                        if self.config['invert_y']: dy_scaled = -dy_scaled

                        packet.delta_x += dx_scaled
                        packet.delta_y += dy_scaled
                        packet.scroll_delta += float(scroll)

                        buttons = self.capture.get_buttons()
                        packet.sequence = (packet.sequence + 1) % 0xFFFFFFFF
                        packet.enabled = 1 if self.enabled else 0

                        btn_mask = 0
                        for btn_name, binding in self.config['mouse_bindings'].items():
                            if binding != "None" and binding in BUTTON_FLAGS:
                                is_pressed = False
                                if btn_name == "left": is_pressed = buttons.get('left', False)
                                elif btn_name == "right": is_pressed = buttons.get('right', False)
                                elif btn_name == "middle": is_pressed = buttons.get('middle', False)
                                elif btn_name == "mouse4": is_pressed = buttons.get('x1', False)
                                elif btn_name == "mouse5": is_pressed = buttons.get('x2', False)
                                if is_pressed: btn_mask |= BUTTON_FLAGS[binding]
                        packet.buttons = btn_mask

                        if buttons.get('middle', False): packet.raw_buttons |= 0x04
                        else: packet.raw_buttons &= ~0x04

                        data = packet.pack()

                        success = False
                        if sys.platform == 'win32':
                            success = pipe_client.write(data)

                            status = pipe_client.read_status()
                            if status:
                                self._dll_status = status['message']
                                self._dll_status_code = status['code']
                        else:
                            success_count = 0
                            for addr in self._target_addresses:
                                if scanner.write(addr, data): success_count += 1
                            if success_count > 0: success = True

                        if not success:
                            raise Exception("Write failed")

                        time.sleep(0.016)

                        if self._scan_requested:
                             self._scan_requested = False

                    except Exception as e:
                        self._mem_connected = False
                        if sys.platform == 'win32': pipe_client.close()
                        time.sleep(1)

                time.sleep(0.5)

            except Exception as e:
                print(f"DEBUG: Main loop error: {e}", flush=True)
                time.sleep(1)


    def run(self):
        self.root.mainloop()

if __name__ == '__main__':
    import multiprocessing
    multiprocessing.freeze_support()

    try:
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))

        log_path = os.path.join(base_dir, 'companionlog.txt')

        class FileLogger:
            def __init__(self, filepath):
                self.terminal = sys.stdout
                self.log = open(filepath, "w", encoding='utf-8', buffering=1)

            def write(self, message):
                try:
                    self.log.write(message)
                    self.log.flush()
                except: pass
                if self.terminal:
                    try:
                        self.terminal.write(message)
                    except: pass

            def flush(self):
                self.log.flush()
                if self.terminal:
                    try:
                        self.terminal.flush()
                    except: pass

        sys.stdout = FileLogger(log_path)
        sys.stderr = sys.stdout
        print(f"MouseCam Companion Log Started: {time.ctime()}")
        print(f"Version: 2.0 (Internal Injection)")
    except Exception as e:
        pass

    if sys.platform != 'win32' and os.geteuid() != 0:
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showwarning(
                "Root Required",
                "MouseCam Companion needs root access for raw mouse input.\n\n"
                "Please run with:\n"
                "sudo ./MouseCamCompanion\n\n"
                "The app will start, but input capture may not work."
            )
            root.destroy()
        except:
            print("WARNING: Not running as root. Run with: sudo ./MouseCamCompanion")

    MouseCamApp().run()
