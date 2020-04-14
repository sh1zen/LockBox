cmake_minimum_required(VERSION 3.15)
project(LockBox)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_CXX_FLAGS_RELEASE "-O3")

#Set Linker flags
set(CMAKE_EXE_LINKER_FLAGS "-static")

link_libraries(ws2_32 wsock32)

include_directories(.)

add_executable(LockBox
        crypto.cpp
        iNode/iNode.cpp
        main.cpp
        md5.cpp
        mman.cpp
        utility.cpp
        io_helpers.cpp io_helpers.h)
