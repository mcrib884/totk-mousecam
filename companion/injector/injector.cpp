#include <windows.h>
#include <vector>
#include <thread>
#include <atomic>
#include <iostream>

#define PIPE_NAME "\\\\.\\pipe\\totk_mousecam"
#define STATUS_PIPE_NAME "\\\\.\\pipe\\totk_mousecam_status"
const uint32_t MAGIC_VALUE = 0x4D4F5553;

#pragma pack(push, 1)
struct SharedMouseData {
    uint32_t magic;
    uint32_t version;
    float deltaX;
    float deltaY;
    float scrollDelta;
    uint32_t buttons;
    uint32_t sequence;
    uint8_t enabled;
    uint8_t rawButtons;
    uint8_t padding[2];
};

struct StatusMessage {
    uint32_t magic;
    uint32_t statusCode;
    uint32_t targetCount;
    char message[64];
};
#pragma pack(pop)

HANDLE g_statusPipe = INVALID_HANDLE_VALUE;

std::atomic<bool> g_running(true);
HMODULE g_hModule = NULL;

void Log(const char* fmt, ...) {
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    strcat_s(path, "totk_injector_debug.txt");
    
    FILE* f = fopen(path, "a");
    if (f) {
        va_list args;
        va_start(args, fmt);
        vfprintf(f, fmt, args);
        fprintf(f, "\n");
        va_end(args);
        fclose(f);
    }
}

enum StatusCode {
    STATUS_IDLE = 0,
    STATUS_SCANNING = 1,
    STATUS_FOUND = 2,
    STATUS_CONNECTED = 3,
    STATUS_ERROR = 4
};

void SendStatus(HANDLE hPipe, StatusCode code, int targetCount, const char* msg) {
    StatusMessage status;
    status.magic = 0x53544154;
    status.statusCode = (uint32_t)code;
    status.targetCount = (uint32_t)targetCount;
    memset(status.message, 0, sizeof(status.message));
    if (msg) {
        strncpy_s(status.message, msg, sizeof(status.message) - 1);
    }
    
    DWORD bytesWritten;
    WriteFile(hPipe, &status, sizeof(status), &bytesWritten, NULL);
    Log("Status sent: code=%d, targets=%d, msg=%s", code, targetCount, msg ? msg : "");
}

std::vector<uintptr_t> ScanForMagic() {
    std::vector<uintptr_t> found;
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    uint8_t* currentAddr = (uint8_t*)sysInfo.lpMinimumApplicationAddress;
    uint8_t* maxAddr = (uint8_t*)0x7FFFFFFFFFFF; 
    
    Log("Scan started.");
    
    uint8_t magicBytes[4];
    memcpy(magicBytes, &MAGIC_VALUE, 4);

    MEMORY_BASIC_INFORMATION mbi;
    while (currentAddr < maxAddr) {
        if (VirtualQuery(currentAddr, &mbi, sizeof(mbi)) == 0) break;

        if (mbi.State == MEM_COMMIT && 
           (mbi.Type == MEM_MAPPED || mbi.Type == MEM_PRIVATE) &&
           (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            
            uint8_t* p = (uint8_t*)mbi.BaseAddress;
            size_t scanSize = mbi.RegionSize;
            
            try {
                for (size_t i = 0; i < scanSize - 32; i += 64) {
                     if (*(uint32_t*)(p + i) == MAGIC_VALUE) {
                         uint32_t ver = *(uint32_t*)(p + i + 4);
                         if (ver == 1) {
                             Log("FOUND ALIGNED MAGIC at %p", p + i);
                             found.push_back((uintptr_t)(p + i));
                         }
                     }
                }
            } catch (...) {
                Log("Exception reading region %p", p);
            }
        }
        currentAddr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
    }
    
    Log("Scan complete. Found %d targets.", found.size());
    return found;
}

DWORD WINAPI PipeThread(LPVOID lpParam) {
    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
    
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    HANDLE hPipe = CreateNamedPipeA(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        1024,
        1024,
        0,
        &sa
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        return 0;
    }

    std::vector<uintptr_t> targets;
    bool needsScan = true;

    while (g_running) {
        if (ConnectNamedPipe(hPipe, NULL) != FALSE || GetLastError() == ERROR_PIPE_CONNECTED) {
            
            if (needsScan || targets.empty()) {
                SendStatus(hPipe, STATUS_SCANNING, 0, "Scanning for game memory...");
                targets = ScanForMagic();
                needsScan = false;
                
                if (targets.empty()) {
                    SendStatus(hPipe, STATUS_ERROR, 0, "No targets found - is game running?");
                } else {
                    SendStatus(hPipe, STATUS_FOUND, (int)targets.size(), "Ready");
                }
            } else {
                SendStatus(hPipe, STATUS_CONNECTED, (int)targets.size(), "Connected - writing data");
            }

            SharedMouseData packet;
            DWORD bytesRead;
            
            while (ReadFile(hPipe, &packet, sizeof(packet), &bytesRead, NULL)) {
                if (bytesRead == sizeof(packet)) {
                    if (packet.magic == 0xDEADBEEF) {
                        SendStatus(hPipe, STATUS_SCANNING, 0, "Re-scanning...");
                        targets = ScanForMagic();
                        if (targets.empty()) {
                            SendStatus(hPipe, STATUS_ERROR, 0, "Re-scan: No targets found");
                        } else {
                            SendStatus(hPipe, STATUS_FOUND, (int)targets.size(), "Ready");
                        }
                        continue;
                    }

                    for (uintptr_t addr : targets) {
                        try {
                            memcpy((void*)addr, &packet, sizeof(packet));
                        } catch (...) {
                            needsScan = true;
                            targets.clear();
                            SendStatus(hPipe, STATUS_ERROR, 0, "Memory write failed - rescan needed");
                            break;
                        }
                    }
                }
            }
            
            DisconnectNamedPipe(hPipe);
        } else {
            Sleep(100);
        }
    }

    CloseHandle(hPipe);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        HANDLE hThread = CreateThread(NULL, 0, PipeThread, NULL, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
