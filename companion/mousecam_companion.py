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

# Memory scan region size preferences (MB). Order matters.
# These correspond to common contiguous guest-RAM mappings in Switch emulators.
PREFERRED_REGION_SIZES_MB = [6144, 4096, 8192]
PREFERRED_REGION_SIZE_TOLERANCE_MB = 16

CHUNK_SIZE = 50 * 1024 * 1024
MIN_REGION_SIZE = 1 * 1024 * 1024
PRIORITY_ALIGNMENT = 256 * 1024 * 1024


def _preferred_region_rank(size_bytes):
    tol = PREFERRED_REGION_SIZE_TOLERANCE_MB * 1024 * 1024
    size_bytes = int(size_bytes)
    for i, mb in enumerate(PREFERRED_REGION_SIZES_MB):
        pref = mb * 1024 * 1024
        if abs(size_bytes - pref) <= tol:
            return i
    return None


if sys.platform == 'win32':
    import ctypes
    from ctypes import wintypes
    import keyboard as keyboard_lib

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    psapi = ctypes.WinDLL('psapi', use_last_error=True)

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020

    MEM_COMMIT = 0x1000
    MEM_MAPPED = 0x40000
    MEM_PRIVATE = 0x20000

    PAGE_NOACCESS = 0x01
    PAGE_READWRITE = 0x04
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_GUARD = 0x100

    TH32CS_SNAPPROCESS = 0x00000002

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

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

    kernel32.Process32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    kernel32.Process32First.restype = wintypes.BOOL

    kernel32.Process32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    kernel32.Process32Next.restype = wintypes.BOOL

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE

    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t

    kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL

    kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.WriteProcessMemory.restype = wintypes.BOOL

    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL

    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
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
        self.can_write = False
        self._written = ctypes.c_size_t(0)

    def _get_working_set(self, pid):
        h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not h:
            return 0
        try:
            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
                return int(pmc.WorkingSetSize)
        finally:
            kernel32.CloseHandle(h)
        return 0

    def find_process(self, process_names):
        want = {p.lower() for p in process_names}

        hSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not hSnap:
            return None, None

        processes = {}
        candidates = []

        pe32 = PROCESSENTRY32()
        pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

        try:
            if kernel32.Process32First(hSnap, ctypes.byref(pe32)):
                while True:
                    exe = pe32.szExeFile.decode('ansi', errors='ignore')
                    pid = int(pe32.th32ProcessID)
                    ppid = int(pe32.th32ParentProcessID)

                    processes[pid] = {'name': exe, 'ppid': ppid}
                    if exe.lower() in want:
                        candidates.append(pid)

                    if not kernel32.Process32Next(hSnap, ctypes.byref(pe32)):
                        break
        finally:
            kernel32.CloseHandle(hSnap)

        if not candidates:
            return None, None

        children = {}
        for pid, info in processes.items():
            children.setdefault(info.get('ppid', 0), []).append(pid)

        final = set(candidates)
        queue_pids = list(candidates)
        while queue_pids:
            parent = queue_pids.pop(0)
            for child in children.get(parent, []):
                if child not in final:
                    final.add(child)
                    queue_pids.append(child)

        best_pid = None
        best_ws = -1
        for pid in final:
            ws = self._get_working_set(pid)
            if ws > best_ws:
                best_ws = ws
                best_pid = pid

        if best_pid is None:
            best_pid = max(final)

        desired = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        h = kernel32.OpenProcess(desired, False, best_pid)
        can_write = True
        if not h:
            desired = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
            h = kernel32.OpenProcess(desired, False, best_pid)
            can_write = False

        if not h:
            self.reset()
            return None, None

        self.reset()
        self.pid = best_pid
        self.handle = h
        self.can_write = can_write

        return processes.get(best_pid, {}).get('name', ''), best_pid

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
        self.can_write = False

    def scan(self, pid):
        if not self.handle:
            return []

        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        found_addresses = []

        regions = []
        while kernel32.VirtualQueryEx(self.handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            region_base = int(mbi.BaseAddress) if mbi.BaseAddress else int(address)
            region_size = int(mbi.RegionSize)
            if region_size <= 0:
                break

            protect = int(mbi.Protect)
            is_committed = (mbi.State == MEM_COMMIT)
            is_target_type = (mbi.Type == MEM_MAPPED) or (mbi.Type == MEM_PRIVATE)
            is_rw = bool(protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))
            is_bad = bool(protect & (PAGE_GUARD | PAGE_NOACCESS))

            if is_committed and is_target_type and is_rw and (not is_bad) and region_size >= MIN_REGION_SIZE:
                pref_rank = _preferred_region_rank(region_size)
                pref_bucket = 0 if pref_rank is not None else 1
                aligned_bucket = 0 if (region_size % PRIORITY_ALIGNMENT == 0) else 1
                type_bucket = 0 if (mbi.Type == MEM_MAPPED) else 1
                regions.append((
                    pref_bucket,
                    pref_rank if pref_rank is not None else 999,
                    aligned_bucket,
                    type_bucket,
                    -region_size,
                    region_base,
                    region_size,
                ))

            address = region_base + region_size

        regions.sort()

        for _, _, _, _, _, region_addr, region_size in regions:
            try:
                read_offset = 0
                while read_offset < region_size:
                    size_to_read = min(CHUNK_SIZE, region_size - read_offset)
                    buffer = ctypes.create_string_buffer(size_to_read)
                    bytes_read = ctypes.c_size_t(0)

                    if kernel32.ReadProcessMemory(
                        self.handle,
                        ctypes.c_void_p(region_addr + read_offset),
                        buffer,
                        size_to_read,
                        ctypes.byref(bytes_read),
                    ):
                        raw = buffer.raw[:bytes_read.value]
                        idx = raw.find(self.magic_bytes)
                        if idx != -1 and (idx + 8) <= len(raw):
                            version = struct.unpack('<I', raw[idx + 4:idx + 8])[0]
                            if version == 1:
                                found_addr = region_addr + read_offset + idx
                                found_addresses.append(found_addr)
                                return found_addresses

                    read_offset += CHUNK_SIZE
            except Exception:
                pass

        return found_addresses

    def write(self, address, data):
        if not self.handle:
            return False
        if not isinstance(data, (bytes, bytearray)):
            data = bytes(data)
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        return bool(
            kernel32.WriteProcessMemory(
                self.handle,
                ctypes.c_void_p(address),
                ctypes.byref(buf),
                len(data),
                ctypes.byref(self._written),
            )
        )


class LinuxScanner(MemoryScanner):
    def __init__(self):
        super().__init__()
        self.mem_file = None
        self.pid = 0
        self.scan_attempt = 0

    def find_process(self, process_names):
        print(f"[SCAN] Searching for processes: {process_names}")

        candidates = []
        process_info = {}
        scanned_count = 0

        try:
            for pid_str in os.listdir('/proc'):
                if not pid_str.isdigit(): continue
                pid = int(pid_str)
                scanned_count += 1

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
                        print(f"[SCAN] Match: PID {pid} name='{info['name']}' RSS={info['rss']}kB")
                        candidates.append(pid)

                except Exception:
                    continue
        except Exception as e:
            print(f"[SCAN] FAIL: Error listing /proc: {e}")
            return None, None

        print(f"[SCAN] Scanned {scanned_count} processes, {len(candidates)} candidates")

        if not candidates:
            print("[SCAN] No matching process found")
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
                        print(f"[SCAN] Child: PID {child} name='{child_name}' RSS={child_rss}kB")

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
            print(f"[SCAN] Selected: PID {best_pid} name='{best_name}' RSS={max_rss}kB")
            self.pid = best_pid
            return best_name, best_pid

        print("[SCAN] No suitable process found after filtering")
        return None, None

    def scan(self, pid):
        self.scan_attempt += 1
        print(f"[SCAN] ===== Attempt #{self.scan_attempt} for PID {pid} =====")
        
        maps_path = f'/proc/{pid}/maps'
        mem_path = f'/proc/{pid}/mem'
        found = []

        MAX_REGION_SIZE = 16 * 1024 * 1024 * 1024

        try:
            self.mem_file = open(mem_path, 'r+b', buffering=0)
            print(f"[SCAN] Opened {mem_path}")
        except PermissionError as e:
            print(f"[SCAN] FAIL: Permission denied opening {mem_path}")
            print(f"[SCAN] Run with: sudo ./MouseCamCompanion")
            return found
        except Exception as e:
            print(f"[SCAN] FAIL: Cannot open {mem_path}: {e}")
            return found

        regions = []
        try:
            with open(maps_path, 'r') as maps:
                for line in maps:
                    parts = line.split()
                    if len(parts) < 2: continue
                    perms = parts[1]
                    if 'r' not in perms or 'w' not in perms: continue

                    addr_range = parts[0].split('-')
                    start = int(addr_range[0], 16)
                    end = int(addr_range[1], 16)
                    size = end - start

                    if size < MIN_REGION_SIZE or size > MAX_REGION_SIZE: continue

                    path = parts[5] if len(parts) > 5 else ''
                    regions.append({'start': start, 'size': size, 'perms': perms, 'path': path})

        except Exception as e:
            print(f"[SCAN] FAIL: Cannot read {maps_path}: {e}")
            return found

        # Split into priority and others
        priority_regions = []
        other_regions = []

        for r in regions:
            # Check if size is a multiple of 256MB
            if r['size'] % PRIORITY_ALIGNMENT == 0:
                priority_regions.append(r)
            else:
                other_regions.append(r)

        def _sort_key(r):
            rank = _preferred_region_rank(r['size'])
            return (0 if rank is not None else 1, rank if rank is not None else 999, -r['size'])

        # Sort priority regions (emulator RAM blocks are usually aligned, but prefer known sizes first)
        priority_regions.sort(key=_sort_key)
        # Sort others similarly
        other_regions.sort(key=_sort_key)

        scan_passes = [
            ("PRIORITY", priority_regions),
            ("FALLBACK", other_regions)
        ]

        regions_scanned = 0
        bytes_scanned = 0
        read_failures = 0

        for pass_name, target_regions in scan_passes:
            if not target_regions: continue
            
            print(f"[SCAN] Starting {pass_name} pass: {len(target_regions)} regions")

            for r in target_regions:
                regions_scanned += 1
                start, size, perms, path = r['start'], r['size'], r['perms'], r['path']
                region_type = "anon" if (path == '' or path.startswith('[')) else "file"

                print(f"[SCAN] Checking {hex(start)} size={size/1024/1024:.1f}MB ({pass_name})", flush=True)

                try:
                    read_offset = 0
                    while read_offset < size:
                        size_to_read = min(CHUNK_SIZE, size - read_offset)
                        addr = start + read_offset
                        
                        try:
                            self.mem_file.seek(addr)
                            chunk = self.mem_file.read(size_to_read)
                            bytes_scanned += len(chunk) if chunk else 0
                        except Exception as e:
                            read_failures += 1
                            if read_failures <= 5:
                                print(f"[SCAN] Read fail: {hex(addr)}: {e}", flush=True)
                            break

                        if not chunk: break

                        idx = chunk.find(self.magic_bytes)
                        if idx != -1:
                            if idx + 8 <= len(chunk):
                                ver = struct.unpack('<I', chunk[idx+4:idx+8])[0]
                                if ver == 1:
                                    found_addr = start + read_offset + idx
                                    print(f"[SCAN] SUCCESS: Magic found at {hex(found_addr)}")
                                    found.append(found_addr)
                                    return found

                        read_offset += CHUNK_SIZE

                except Exception as e:
                    continue

        print(f"[SCAN] FAIL: Magic not found after scanning {regions_scanned} regions")
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
            print("[WRITE] FAIL: No mem_file handle", flush=True)
            return False
        try:
            self.mem_file.seek(address)
            self.mem_file.write(data)
            self.mem_file.flush()
            return True
        except Exception as e:
            print(f"[WRITE] FAIL: {hex(address)}: {e}", flush=True)
            return False

    def reset(self):
        print(f"[SCAN] Reset: closing PID {self.pid}")
        if self.mem_file:
            try:
                self.mem_file.close()
            except:
                pass
        self.mem_file = None
        self.pid = 0

DEFAULT_CONFIG = {
    "emulator_path": "",
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
                loaded = json.load(f) or {}

                # Only accept known keys (older versions may have extra fields)
                config = DEFAULT_CONFIG.copy()
                config['mouse_bindings'] = DEFAULT_CONFIG['mouse_bindings'].copy()

                for key, value in loaded.items():
                    if key == 'mouse_bindings':
                        continue
                    if key in config:
                        config[key] = value

                if isinstance(loaded.get('mouse_bindings'), dict):
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
        
        if sys.platform != 'win32':
            try:
                btn_map[pynput_mouse.Button.button8] = 'x1'
                btn_map[pynput_mouse.Button.button9] = 'x2'
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
        ttk.Scale(sens_row, from_=0.1, to=5.0, variable=self.sens_var, orient=tk.HORIZONTAL, length=180).pack(side=tk.LEFT, padx=5)
        self.sens_label = ttk.Label(sens_row, text=f"{self.sens_var.get():.1f}")
        self.sens_label.pack(side=tk.LEFT)

        self.invert_var = tk.BooleanVar(value=self.config['invert_y'])
        self.invert_var.trace_add('write', lambda *_: self._auto_save())
        ttk.Checkbutton(settings_frame, text="Invert Y", variable=self.invert_var).pack(anchor=tk.W)

        bind_frame = ttk.LabelFrame(parent, text="Mouse → Gamepad", padding="10")
        bind_frame.pack(fill=tk.X)

        tools_frame = ttk.Frame(parent)
        tools_frame.pack(fill=tk.X, pady=10)

        self.scan_btn = ttk.Button(tools_frame, text="Scan Memory", command=self._request_scan)
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
        else:
            scanner = LinuxScanner()

        self._target_addresses = []
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

                process_name, pid = scanner.find_process(target_process_names)

                if not pid:
                    self._mem_connected = False
                    self._target_addresses = []
                    try:
                        scanner.reset()
                    except Exception:
                        pass
                    self._mem_status = "Waiting for Emulator..."
                    self._update_ui()
                    time.sleep(1)
                    continue

                self._mem_status = f"Found {process_name} ({pid})"
                self._update_ui()

                if self._scan_requested:
                    self._mem_status = "Scanning..."
                    self._update_ui()

                    addrs = scanner.scan(pid)
                    if addrs:
                        self._target_addresses = addrs
                        self.capture.emulator_process_name = process_name

                        if sys.platform == 'win32' and not getattr(scanner, 'can_write', True):
                            self._mem_connected = False
                            self._mem_status = "Scan OK but no write access (run as admin)"
                        else:
                            self._mem_connected = True
                            self._mem_status = f"Connected ({len(addrs)} addrs)"
                    else:
                        self._mem_connected = False
                        self._target_addresses = []
                        self._mem_status = "Scan Failed - Not Found"

                    self._scan_requested = False
                    self._update_ui()

                while self._mem_connected:
                    if not scanner.is_process_alive():
                        self._mem_connected = False
                        break

                    try:
                        dx, dy, scroll = self.capture.get_and_reset_delta()

                        # Mouse → right stick scale
                        # Baseline is 1/3 of the previous behavior (previous was `0.5 * sensitivity`).
                        RIGHT_STICK_BASE_SCALE = (0.5 / 3.0)
                        scale = float(self.config['sensitivity']) * RIGHT_STICK_BASE_SCALE
                        dx_scaled = float(dx) * scale
                        dy_scaled = float(dy) * scale
                        if self.config['invert_y']:
                            dy_scaled = -dy_scaled

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
                                if btn_name == "left":
                                    is_pressed = buttons.get('left', False)
                                elif btn_name == "right":
                                    is_pressed = buttons.get('right', False)
                                elif btn_name == "middle":
                                    is_pressed = buttons.get('middle', False)
                                elif btn_name == "mouse4":
                                    is_pressed = buttons.get('x1', False)
                                elif btn_name == "mouse5":
                                    is_pressed = buttons.get('x2', False)
                                if is_pressed:
                                    btn_mask |= BUTTON_FLAGS[binding]
                        packet.buttons = btn_mask

                        if buttons.get('middle', False):
                            packet.raw_buttons |= 0x04
                        else:
                            packet.raw_buttons &= ~0x04

                        data = packet.pack()

                        success_count = 0
                        for addr in self._target_addresses:
                            if scanner.write(addr, data):
                                success_count += 1

                        if success_count <= 0:
                            raise Exception("Write failed")

                        time.sleep(0.016)

                        if self._scan_requested:
                            self._scan_requested = False

                    except Exception:
                        self._mem_connected = False
                        self._mem_status = "Disconnected"
                        self._update_ui()
                        time.sleep(1)

                try:
                    scanner.reset()
                except Exception:
                    pass

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
        print(f"Version: 2.1 (Memory Scan)")
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
