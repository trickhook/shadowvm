cmake_minimum_required(VERSION 3.22)
project(shadowvm C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_compile_options(
    -Wall -Wextra -Wno-unused-parameter
    -fno-strict-aliasing
    -fvisibility=hidden
    -ffunction-sections -fdata-sections
    -fno-plt
)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2 -fno-stack-protector)
    add_link_options(-Wl,--gc-sections -Wl,--strip-all)
endif()

file(GLOB SHADOWVM_SOURCES "src/*.c")

add_library(shadowvm SHARED ${SHADOWVM_SOURCES})
target_include_directories(shadowvm PUBLIC include)
target_link_options(shadowvm PRIVATE -Wl,-z,now -Wl,-z,relro)

add_library(shadowvm_static STATIC ${SHADOWVM_SOURCES})
target_include_directories(shadowvm_static PUBLIC include)
