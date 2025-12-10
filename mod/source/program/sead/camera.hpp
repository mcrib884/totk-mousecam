#pragma once

#include "sead/math.hpp"

namespace sead {

// Forward declaration of camera base class
class Camera {
public:
    virtual ~Camera() = default;
    virtual void doUpdateMatrix() = 0;
    
    Matrix34f mMatrix;  // View matrix
};

// LookAtCamera: the camera type TOTK uses
// Based on reverse engineering of sead library
class LookAtCamera : public Camera {
public:
    // Offset 0x38 from start (after vtable + Matrix34f)
    Vector3f mPos;   // Camera position
    Vector3f mAt;    // Look-at target
    Vector3f mUp;    // Up vector
    
    // doUpdateMatrix computes mMatrix from mPos, mAt, mUp
    virtual void doUpdateMatrix() override;
};

} // namespace sead
