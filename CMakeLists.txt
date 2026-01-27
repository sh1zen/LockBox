cmake_minimum_required(VERSION 3.15)

project(LockBox VERSION 1.0.0 LANGUAGES CXX)

# Use C++23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optimizations
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

# Static linking (Windows-only recommended)
if (WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

# ======================= SOURCES =======================
set(COMMON_SOURCES
        mman.cpp
        filesystem.cpp
        OpenES/support/base64/base64.cpp
        OpenES/OES.cpp
        OpenES/layer/raw-layer.cpp
        OpenES/layer/interface.cpp
        OpenES/algo/block_ciphers.cpp
        OpenES/support/big_int/big_int.cpp
        OpenES/algo/asymmetric.cpp
        OpenES/algo/hashing.cpp
        OpenES/support/support.cpp
        OpenES/support/oes-exception.cpp
        OpenES/algo/key_management.cpp
        OpenES/support/oesMath.cpp
        iNode/Block.cpp
        iNode/iNode.cpp
        iNode/inode_raw.cpp
        OpenES/layer/m_block.h
        OpenES/layer/m_block.cpp
        OpenES/algo/constants.h
        OpenES/algo/core.cpp
        OpenES/algo/core.h
        OpenES/algo/utils.cpp
        OpenES/algo/utils.h
        OpenES/algo/prng.cpp
        OpenES/algo/prng.h
        OpenES/algo/sphinix.cpp
        OpenES/algo/sphinix.h
        iNode/inode_raw.h
)

set(APP_SOURCES
        main.cpp
        OpenES/layer/defines.h
)

set(TEST_SOURCES
        test/tester.h
        test/oes_tests.cpp
        test/prngtest.cpp
        test/prngtest.h
)

# ======================= INCLUDE DIRECTORIES =======================
include_directories(
        .
        OpenES
        OpenES/support
        OpenES/layer
        OpenES/algo
        OpenES/interface
        iNode
)

# ======================= OPTIONS =======================
option(BUILD_APP "Build the main application" ON)
option(BUILD_TESTS "Build the test suite" OFF)

# ======================= EXECUTABLES =======================
if (BUILD_APP)
    add_executable(LockBox ${COMMON_SOURCES} ${APP_SOURCES})
    target_compile_options(LockBox PRIVATE
            $<$<CONFIG:Release>:-O3 -march=native -funroll-loops>
    )
    if (WIN32)
        target_link_libraries(LockBox PRIVATE ws2_32)
    endif()
endif()

if (BUILD_TESTS)
    add_compile_definitions(DEBUG=1)
    add_executable(LockBoxTests ${COMMON_SOURCES} ${TEST_SOURCES})
    if (WIN32)
        target_link_libraries(LockBoxTests PRIVATE ws2_32)
    endif()
endif()
