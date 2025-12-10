#pragma once

#include <cstdint>
#include <cstring>

/**
 * Platform-independent mouse input via file-based IPC
 * 
 * The companion tool writes mouse delta to a known file location.
 * The mod reads from this file each frame.
 * 
 * File format (16 bytes):
 *   float deltaX (4 bytes)
 *   float deltaY (4 bytes)  
 *   uint32_t buttons (4 bytes)
 *   uint32_t sequence (4 bytes) - increments each write
 */

namespace MouseIPC {

struct MouseData {
    float deltaX;
    float deltaY;
    uint32_t buttons;
    uint32_t sequence;
};

// For Switch/emulator, we'll use a simpler approach:
// nn::hid::Mouse when available (emulator), or
// a memory-mapped region that companion tool can write to

// Global state
inline MouseData g_lastData = {0, 0, 0, 0};
inline uint32_t g_lastSequence = 0;
inline bool g_initialized = false;

// On emulator, we can use nn::hid::Mouse directly
// This provides mouse support in yuzu/Ryujinx without external tools

#ifdef USE_NN_HID_MOUSE
#include <nn/hid.h>

inline void Initialize() {
    nn::hid::InitializeMouse();
    g_initialized = true;
}

inline void ReadDelta(float& outDeltaX, float& outDeltaY) {
    nn::hid::MouseState state;
    nn::hid::GetMouseState(&state);
    
    // Mouse delta is the difference from last position
    static int32_t lastX = 0, lastY = 0;
    static bool firstRead = true;
    
    if (firstRead) {
        lastX = state.x;
        lastY = state.y;
        firstRead = false;
        outDeltaX = 0;
        outDeltaY = 0;
        return;
    }
    
    outDeltaX = static_cast<float>(state.x - lastX);
    outDeltaY = static_cast<float>(state.y - lastY);
    lastX = state.x;
    lastY = state.y;
}

#else

// Fallback: No external input, use right stick as mouse substitute
// This allows testing the rotation logic without mouse support

inline void Initialize() {
    g_initialized = true;
}

inline void ReadDelta(float& outDeltaX, float& outDeltaY) {
    // Without external input, return zero
    // The companion tool approach would write to shared memory here
    outDeltaX = 0.0f;
    outDeltaY = 0.0f;
}

#endif

} // namespace MouseIPC
