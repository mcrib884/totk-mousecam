#pragma once

#include <cstdint>
#include <cmath>

namespace sead {

// Basic vector types
struct Vector3f {
    float x, y, z;
    
    Vector3f() : x(0), y(0), z(0) {}
    Vector3f(float x_, float y_, float z_) : x(x_), y(y_), z(z_) {}
    
    Vector3f operator-(const Vector3f& o) const { return {x - o.x, y - o.y, z - o.z}; }
    Vector3f operator+(const Vector3f& o) const { return {x + o.x, y + o.y, z + o.z}; }
    Vector3f operator*(float s) const { return {x * s, y * s, z * s}; }
    
    float length() const { return sqrtf(x*x + y*y + z*z); }
    
    Vector3f normalized() const {
        float len = length();
        if (len > 0.0001f) return {x/len, y/len, z/len};
        return {0, 0, 0};
    }
    
    static Vector3f cross(const Vector3f& a, const Vector3f& b) {
        return {
            a.y * b.z - a.z * b.y,
            a.z * b.x - a.x * b.z,
            a.x * b.y - a.y * b.x
        };
    }
    
    static float dot(const Vector3f& a, const Vector3f& b) {
        return a.x * b.x + a.y * b.y + a.z * b.z;
    }
};

// 3x4 matrix (row major, no bottom row stored since it's always 0,0,0,1)
struct Matrix34f {
    float m[3][4];
    
    Matrix34f() {
        for (int i = 0; i < 3; i++)
            for (int j = 0; j < 4; j++)
                m[i][j] = (i == j) ? 1.0f : 0.0f;
    }
};

} // namespace sead
