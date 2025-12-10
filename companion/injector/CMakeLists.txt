cmake_minimum_required(VERSION 3.10)
project(MouseCamInjector)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /MANIFEST:NO")

add_library(MouseCamInjector SHARED injector.cpp)
