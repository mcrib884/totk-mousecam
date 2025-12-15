#include "lib.hpp"
#include "loggers.hpp"
#include "nn/hid.h"
#include <cmath>
#include <cstring>
constexpr uintptr_t PAUSE_MGR_INSTANCE = 0x04728688;
constexpr uintptr_t PAUSE_FLAGS_OFFSET = 0x30;

static uintptr_t s_moduleBase = 0;

uintptr_t GetModuleBase() {
    if (s_moduleBase == 0) {
        s_moduleBase = exl::util::GetMainModuleInfo().m_Text.m_Start;
    }
    return s_moduleBase;
}

namespace MouseCam {
    int g_frameCount = 0;
    float g_yaw = 0.0f;
    float g_pitch = 0.0f;
    bool g_initialized = false;
    float g_sensitivity = 0.003f;
    float g_zoomStep = 1.0f;
    float g_zoomLerp = 0.15f;
    float g_minRadius = 2.0f;
    float g_maxRadius = 25.0f;
    bool g_ipcAvailable = false;
    bool g_sdMounted = false;
    bool g_fileChecked = false;
    uint32_t g_lastSequence = 0;
    uint32_t g_mappedButtons = 0;
    float g_accumulatedDeltaX = 0.0f;
    float g_accumulatedDeltaY = 0.0f;
    float g_accumulatedScroll = 0.0f;
    float g_smoothedScroll = 0.0f;
    bool g_resetZoom = false;
    bool g_captureEnabled = false;
    float g_savedRadius = 5.0f;
    float g_targetRadius = 5.0f;
    bool g_firstZoom = true;
    float g_defaultRadius = 5.0f;
    bool g_inMenu = false;
    float g_menuStickX = 0.0f;
    float g_menuStickY = 0.0f;
}

bool IsGamePaused() {
    uintptr_t base = GetModuleBase();
    uintptr_t* pInstance = reinterpret_cast<uintptr_t*>(base + PAUSE_MGR_INSTANCE);
    if (pInstance == nullptr || *pInstance == 0) return false;
    
    uintptr_t instance = *pInstance;
    uint32_t* pFlags = reinterpret_cast<uint32_t*>(instance + PAUSE_FLAGS_OFFSET);
    if (pFlags == nullptr) return false;
    
    return *pFlags != 0;
}

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
#pragma pack(pop)

static_assert(sizeof(SharedMouseData) == 32, "SharedMouseData must be 32 bytes");

constexpr uint32_t SHARED_MOUSE_MAGIC = 0x4D4F5553;
constexpr uint32_t SHARED_MOUSE_VERSION = 1;

namespace MemoryIpc {
    alignas(64) static volatile SharedMouseData g_sharedData = {
        SHARED_MOUSE_MAGIC,
        SHARED_MOUSE_VERSION,
        0.0f, 0.0f, 0.0f,
        0, 0,
        0, 0, {0, 0}
    };
    
    static bool g_initialized = false;
    
    void Initialize() {
        if (g_initialized) return;
        g_sharedData.magic = SHARED_MOUSE_MAGIC;
        g_sharedData.version = SHARED_MOUSE_VERSION;
        g_sharedData.sequence = 0;
        g_sharedData.enabled = 0;
        Logging.Log("MouseCam: SharedMemory @ %p (magic=0x%X)", &g_sharedData, SHARED_MOUSE_MAGIC);
        g_initialized = true;
    }
    
    bool ReadPacket(SharedMouseData* outData) {
        if (!g_initialized) return false;
        if (g_sharedData.magic != SHARED_MOUSE_MAGIC) return false;
        outData->magic = g_sharedData.magic;
        outData->version = g_sharedData.version;
        outData->deltaX = g_sharedData.deltaX;
        outData->deltaY = g_sharedData.deltaY;
        outData->scrollDelta = g_sharedData.scrollDelta;
        outData->buttons = g_sharedData.buttons;
        outData->sequence = g_sharedData.sequence;
        outData->enabled = g_sharedData.enabled;
        outData->rawButtons = g_sharedData.rawButtons;
        return true;
    }
}

static float s_lastTotalX = 0.0f;
static float s_lastTotalY = 0.0f;
static float s_lastTotalScroll = 0.0f;
static bool s_firstRead = true;

void UpdateMouseFromIPC() {
    if (MouseCam::g_frameCount < 60) return;
    MemoryIpc::Initialize();
    SharedMouseData data;
    if (!MemoryIpc::ReadPacket(&data)) return;
    
    if (!MouseCam::g_ipcAvailable && data.sequence != 0) {
        MouseCam::g_ipcAvailable = true;
        Logging.Log("MouseCam: Companion connected (SharedMem)!");
    }
    
    MouseCam::g_captureEnabled = data.enabled != 0;
    MouseCam::g_mappedButtons = data.buttons;
    MouseCam::g_inMenu = IsGamePaused();
    
    if (data.enabled) {
        if (s_firstRead) {
            s_lastTotalX = data.deltaX;
            s_lastTotalY = data.deltaY;
            s_lastTotalScroll = data.scrollDelta;
            s_firstRead = false;
        }
        float dX = data.deltaX - s_lastTotalX;
        float dY = data.deltaY - s_lastTotalY;
        float dScroll = data.scrollDelta - s_lastTotalScroll;
        s_lastTotalX = data.deltaX;
        s_lastTotalY = data.deltaY;
        s_lastTotalScroll = data.scrollDelta;
        MouseCam::g_accumulatedDeltaX += dX;
        MouseCam::g_accumulatedDeltaY += dY;
        MouseCam::g_accumulatedScroll += dScroll;
        MouseCam::g_lastSequence = data.sequence;
        if (data.rawButtons & 0x04) {
            MouseCam::g_resetZoom = true;
        }
        
        if (MouseCam::g_inMenu) {
            float menuSensitivity = 500.0f;
            MouseCam::g_menuStickX += dX * menuSensitivity;
            MouseCam::g_menuStickY += -dY * menuSensitivity;
            if (MouseCam::g_menuStickX > 32767.0f) MouseCam::g_menuStickX = 32767.0f;
            if (MouseCam::g_menuStickX < -32767.0f) MouseCam::g_menuStickX = -32767.0f;
            if (MouseCam::g_menuStickY > 32767.0f) MouseCam::g_menuStickY = 32767.0f;
            if (MouseCam::g_menuStickY < -32767.0f) MouseCam::g_menuStickY = -32767.0f;
        }
    } else {
        s_firstRead = true;
        MouseCam::g_accumulatedDeltaX = 0;
        MouseCam::g_accumulatedDeltaY = 0;
        MouseCam::g_accumulatedScroll = 0;
        MouseCam::g_menuStickX = 0;
        MouseCam::g_menuStickY = 0;
    }
}

void GetMouseDelta(float& outDeltaX, float& outDeltaY) {
    outDeltaX = MouseCam::g_accumulatedDeltaX;
    outDeltaY = MouseCam::g_accumulatedDeltaY;
    MouseCam::g_accumulatedDeltaX = 0;
    MouseCam::g_accumulatedDeltaY = 0;
}

float GetScrollDelta() {
    float scroll = MouseCam::g_accumulatedScroll;
    MouseCam::g_accumulatedScroll = 0;
    return scroll;
}

constexpr uintptr_t GET_NPAD_STATES_FULLKEY = 0x02b180a0;

HOOK_DEFINE_TRAMPOLINE(GetNpadStatesHook) {
    static void Callback(nn::hid::NpadFullKeyState* states, int count, uint const& port) {
        Orig(states, count, port);
        UpdateMouseFromIPC();
        if (port == 0 && MouseCam::g_captureEnabled) {
            if (states == nullptr) return;
            for (int i = 0; i < count; i++) {
                if (MouseCam::g_mappedButtons != 0) {
                    uint64_t* buttonsPtr = reinterpret_cast<uint64_t*>(&states[i].mButtons);
                    if (buttonsPtr != nullptr) {
                        *buttonsPtr |= MouseCam::g_mappedButtons;
                    }
                }
                if (MouseCam::g_inMenu) {
                    states[i].mAnalogStickR.X = static_cast<int32_t>(MouseCam::g_menuStickX);
                    states[i].mAnalogStickR.Y = static_cast<int32_t>(MouseCam::g_menuStickY);
                    MouseCam::g_menuStickX = 0;
                    MouseCam::g_menuStickY = 0;
                }
            }
        }
    }
};

constexpr uintptr_t GET_NPAD_STATES_HANDHELD = 0x02b18130;

HOOK_DEFINE_TRAMPOLINE(GetNpadStatesHandheldHook) {
    static void Callback(nn::hid::NpadHandheldState* states, int count, uint const& port) {
        Orig(states, count, port);
        UpdateMouseFromIPC();
        if (port == 0 && MouseCam::g_captureEnabled) {
            for (int i = 0; i < count && states != nullptr; i++) {
                if (MouseCam::g_mappedButtons != 0) {
                    uint64_t* buttonsPtr = reinterpret_cast<uint64_t*>(&states[i].mButtons);
                    *buttonsPtr |= MouseCam::g_mappedButtons;
                }
                if (MouseCam::g_inMenu) {
                    states[i].mAnalogStickR.X = static_cast<int32_t>(MouseCam::g_menuStickX);
                    states[i].mAnalogStickR.Y = static_cast<int32_t>(MouseCam::g_menuStickY);
                    MouseCam::g_menuStickX = 0;
                    MouseCam::g_menuStickY = 0;
                }
            }
        }
    }
};

constexpr uintptr_t GET_NPAD_STATES_JOYDUAL = 0x02b18100;

HOOK_DEFINE_TRAMPOLINE(GetNpadStatesJoyDualHook) {
    static void Callback(nn::hid::NpadJoyDualState* states, int count, uint const& port) {
        Orig(states, count, port);
        UpdateMouseFromIPC();
        if (port == 0 && MouseCam::g_captureEnabled) {
            for (int i = 0; i < count && states != nullptr; i++) {
                if (MouseCam::g_mappedButtons != 0) {
                    uint64_t* buttonsPtr = reinterpret_cast<uint64_t*>(&states[i].mButtons);
                    *buttonsPtr |= MouseCam::g_mappedButtons;
                }
                if (MouseCam::g_inMenu) {
                    states[i].mAnalogStickR.X = static_cast<int32_t>(MouseCam::g_menuStickX);
                    states[i].mAnalogStickR.Y = static_cast<int32_t>(MouseCam::g_menuStickY);
                    MouseCam::g_menuStickX = 0;
                    MouseCam::g_menuStickY = 0;
                }
            }
        }
    }
};

constexpr uintptr_t CAMERA_ALPHA_UPDATE = 0x00a70604;

HOOK_DEFINE_TRAMPOLINE(CamAlphaHook) {
    static void Callback(float deltaTime, long param2, long* param3) {
        MouseCam::g_frameCount++;
        UpdateMouseFromIPC();
        Orig(deltaTime, param2, param3);
        
        if (param3 != nullptr && MouseCam::g_captureEnabled && !MouseCam::g_inMenu) {
            if ((uintptr_t)param3 < 0x1000) {
                Logging.Log("CamHook: Bad param3 %p", param3);
                return;
            }
            long cameraData = *param3;
            if (cameraData != 0) {
                float* pPosX = reinterpret_cast<float*>(cameraData + 0x0);
                float* pPosY = reinterpret_cast<float*>(cameraData + 0x4);
                float* pPosZ = reinterpret_cast<float*>(cameraData + 0x8);
                float* pFocX = reinterpret_cast<float*>(cameraData + 0xC);
                float* pFocY = reinterpret_cast<float*>(cameraData + 0x10);
                float* pFocZ = reinterpret_cast<float*>(cameraData + 0x14);
                float* pUpX  = reinterpret_cast<float*>(cameraData + 0x18);
                float* pUpY  = reinterpret_cast<float*>(cameraData + 0x1C);
                float* pUpZ  = reinterpret_cast<float*>(cameraData + 0x20);
                
                float fx = *pFocX, fy = *pFocY, fz = *pFocZ;
                
                if (!MouseCam::g_initialized) {
                    float cx = *pPosX, cy = *pPosY, cz = *pPosZ;
                    float vx = cx - fx;
                    float vy = cy - fy;
                    float vz = cz - fz;
                    MouseCam::g_savedRadius = sqrtf(vx*vx + vy*vy + vz*vz);
                    if (!std::isfinite(MouseCam::g_savedRadius) || MouseCam::g_savedRadius < 0.1f) {
                        MouseCam::g_savedRadius = 5.0f;
                    }
                    MouseCam::g_targetRadius = MouseCam::g_savedRadius;
                    MouseCam::g_defaultRadius = MouseCam::g_savedRadius;
                    MouseCam::g_firstZoom = true;
                    MouseCam::g_yaw = atan2f(vx, vz);
                    MouseCam::g_pitch = asinf(vy / MouseCam::g_savedRadius);
                    if (!std::isfinite(MouseCam::g_yaw)) MouseCam::g_yaw = 0.0f;
                    if (!std::isfinite(MouseCam::g_pitch)) MouseCam::g_pitch = 0.0f;
                    MouseCam::g_initialized = true;
                    Logging.Log("MouseCam: Initialized yaw=%.2f pitch=%.2f radius=%.1f", 
                               MouseCam::g_yaw, MouseCam::g_pitch, MouseCam::g_savedRadius);
                }
                
                float dx = 0.0f, dy = 0.0f;
                GetMouseDelta(dx, dy);
                float scroll = GetScrollDelta();
                
                if (MouseCam::g_resetZoom) {
                    MouseCam::g_targetRadius = MouseCam::g_defaultRadius;
                    MouseCam::g_resetZoom = false;
                }
                
                if (abs(scroll) > 0.01f) {
                    MouseCam::g_targetRadius -= scroll * MouseCam::g_zoomStep;
                    if (MouseCam::g_firstZoom) {
                        MouseCam::g_firstZoom = false;
                    }
                }
                
                if (MouseCam::g_targetRadius < MouseCam::g_minRadius) MouseCam::g_targetRadius = MouseCam::g_minRadius;
                if (MouseCam::g_targetRadius > MouseCam::g_maxRadius) MouseCam::g_targetRadius = MouseCam::g_maxRadius;
                
                float diff = MouseCam::g_targetRadius - MouseCam::g_savedRadius;
                if (abs(diff) < 0.01f) {
                    MouseCam::g_savedRadius = MouseCam::g_targetRadius;
                } else {
                    MouseCam::g_savedRadius += diff * MouseCam::g_zoomLerp;
                }
                
                if (!std::isfinite(MouseCam::g_savedRadius)) {
                    MouseCam::g_savedRadius = 5.0f;
                    MouseCam::g_targetRadius = 5.0f;
                }
                
                nn::hid::NpadFullKeyState pad;
                nn::hid::GetNpadState(&pad, 0);
                float stickX = (float)pad.mAnalogStickR.X / 32768.0f;
                float stickY = (float)pad.mAnalogStickR.Y / 32768.0f;
                if (abs(stickX) > 0.1f) dx -= stickX * 40.0f;
                if (abs(stickY) > 0.1f) dy += stickY * 40.0f;
                
                MouseCam::g_yaw   -= dx * MouseCam::g_sensitivity;
                MouseCam::g_pitch += dy * MouseCam::g_sensitivity;
                
                float limit = 1.55f;
                if (MouseCam::g_pitch > limit) MouseCam::g_pitch = limit;
                if (MouseCam::g_pitch < -limit) MouseCam::g_pitch = -limit;
                
                float new_vy = MouseCam::g_savedRadius * sinf(MouseCam::g_pitch);
                float h = MouseCam::g_savedRadius * cosf(MouseCam::g_pitch);
                float new_vx = h * sinf(MouseCam::g_yaw);
                float new_vz = h * cosf(MouseCam::g_yaw);
                
                *pPosX = fx + new_vx;
                *pPosY = fy + new_vy;
                *pPosZ = fz + new_vz;
                
                *pUpX = 0.0f;
                *pUpY = 1.0f;
                *pUpZ = 0.0f;
            }
        }
    }
};

extern "C" void exl_main(void*, void*) {
    Logging.Log("MouseCam: v6.0 - Menu Detection");
    exl::hook::Initialize();
    CamAlphaHook::InstallAtOffset(CAMERA_ALPHA_UPDATE);
    GetNpadStatesHook::InstallAtOffset(GET_NPAD_STATES_FULLKEY);
    GetNpadStatesHandheldHook::InstallAtOffset(GET_NPAD_STATES_HANDHELD);
    GetNpadStatesJoyDualHook::InstallAtOffset(GET_NPAD_STATES_JOYDUAL);
    Logging.Log("MouseCam: Ready! Start companion app and press F3.");
}

extern "C" NORETURN void exl_exception_entry() {
    EXL_ABORT("MouseCam exception");
}
