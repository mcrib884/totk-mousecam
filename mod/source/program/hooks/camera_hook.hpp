#pragma once

#include "lib/hook/trampoline.hpp"
#include "sead/camera.hpp"
#include "sead/math.hpp"
#include <cmath>

// Forward declare nn::hid mouse functions for emulator
namespace nn::hid {
    struct MouseState {
        int64_t samplingNumber;
        int32_t x;
        int32_t y;
        int32_t deltaX;
        int32_t deltaY;
        int32_t wheelDeltaX;
        int32_t wheelDeltaY;
        int32_t buttons;
        int32_t attributes;
    };
    
    void InitializeMouse();
    void GetMouseStates(MouseState* states, int* count, int maxCount);
}

namespace MouseCam {
    // Configuration
    inline float g_sensitivityX = 0.003f;  // Radians per pixel
    inline float g_sensitivityY = 0.003f;
    inline float g_pitchMin = -1.4f;       // ~-80 degrees
    inline float g_pitchMax = 1.4f;        // ~+80 degrees
    
    // Accumulated rotation state
    inline float g_yaw = 0.0f;
    inline float g_pitch = 0.0f;
    inline bool g_initialized = false;
    inline bool g_mouseEnabled = true;
    
    // Last mouse state for delta calculation
    inline int32_t g_lastMouseX = 0;
    inline int32_t g_lastMouseY = 0;
    inline bool g_firstMouse = true;
    
    // Initialize mouse subsystem (call once)
    inline void InitMouse() {
        if (!g_initialized) {
            nn::hid::InitializeMouse();
            g_initialized = true;
        }
    }
    
    // Read mouse delta from nn::hid (works in emulators)
    inline void GetMouseDelta(float& dx, float& dy) {
        nn::hid::MouseState states[1];
        int count = 0;
        nn::hid::GetMouseStates(states, &count, 1);
        
        if (count > 0) {
            // Use the delta values directly if available
            dx = static_cast<float>(states[0].deltaX);
            dy = static_cast<float>(states[0].deltaY);
        } else {
            dx = 0.0f;
            dy = 0.0f;
        }
    }
    
    // Apply mouse delta to camera before matrix calculation
    inline void ApplyRotation(sead::LookAtCamera* camera) {
        if (!camera || !g_mouseEnabled) return;
        
        // Initialize mouse if needed
        if (!g_initialized) {
            InitMouse();
        }
        
        // Get mouse delta
        float dx, dy;
        GetMouseDelta(dx, dy);
        
        // Skip if no input
        if (dx == 0.0f && dy == 0.0f) return;
        
        // Get camera coordinate system
        sead::Vector3f toCamera = camera->mPos - camera->mAt;
        float distance = toCamera.length();
        if (distance < 0.001f) return;
        
        // Accumulate yaw and pitch from mouse input
        g_yaw -= dx * g_sensitivityX;
        g_pitch -= dy * g_sensitivityY;
        
        // Clamp pitch to prevent flip
        if (g_pitch < g_pitchMin) g_pitch = g_pitchMin;
        if (g_pitch > g_pitchMax) g_pitch = g_pitchMax;
        
        // Calculate new camera position using spherical coordinates
        float cosP = cosf(g_pitch);
        float sinP = sinf(g_pitch);
        float cosY = cosf(g_yaw);
        float sinY = sinf(g_yaw);
        
        // New direction from target to camera
        sead::Vector3f newDir;
        newDir.x = cosP * sinY;
        newDir.y = sinP;
        newDir.z = cosP * cosY;
        
        // Apply new position (maintain distance from target)
        camera->mPos = camera->mAt + (newDir * distance);
        
        // Update up vector to stay oriented
        camera->mUp = sead::Vector3f(0.0f, 1.0f, 0.0f);
    }
}

// Hook for sead::LookAtCamera::doUpdateMatrix
// Address: 0x00a2e4b0 (from totk_syms)
HOOK_DEFINE_TRAMPOLINE(LookAtCameraDoUpdateMatrix) {
    static void Callback(sead::LookAtCamera* camera) {
        // Apply mouse rotation BEFORE the original matrix calculation
        MouseCam::ApplyRotation(camera);
        
        // Call original - this computes the view matrix from mPos/mAt/mUp
        Orig(camera);
    }
};
