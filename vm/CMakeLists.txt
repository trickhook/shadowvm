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
list(FILTER SHADOWVM_SOURCES EXCLUDE REGEX "selftest_main\\.c$")

add_library(shadowvm SHARED ${SHADOWVM_SOURCES})
target_include_directories(shadowvm PUBLIC include)
target_include_directories(shadowvm PRIVATE src)
target_link_options(shadowvm PRIVATE -Wl,-z,now -Wl,-z,relro)

add_library(shadowvm_static STATIC ${SHADOWVM_SOURCES})
target_include_directories(shadowvm_static PUBLIC include)
target_include_directories(shadowvm_static PRIVATE src)

option(SHADOWVM_SELFTEST "Build the shadowvm_selftest executable" OFF)
if(SHADOWVM_SELFTEST)
    target_compile_definitions(shadowvm PRIVATE SVM_CRYPTO_SELFTEST)
    target_compile_definitions(shadowvm_static PRIVATE SVM_CRYPTO_SELFTEST)
    add_executable(shadowvm_selftest src/selftest_main.c)
    target_compile_definitions(shadowvm_selftest PRIVATE SVM_CRYPTO_SELFTEST)
    target_include_directories(shadowvm_selftest PRIVATE include src)
    target_link_libraries(shadowvm_selftest PRIVATE shadowvm_static)
endif()

find_package(CURL QUIET)
if(CURL_FOUND)
    target_compile_definitions(shadowvm PRIVATE SHADOWVM_USE_CURL)
    target_compile_definitions(shadowvm_static PRIVATE SHADOWVM_USE_CURL)
    target_include_directories(shadowvm PRIVATE ${CURL_INCLUDE_DIRS})
    target_include_directories(shadowvm_static PRIVATE ${CURL_INCLUDE_DIRS})
    target_link_libraries(shadowvm PRIVATE ${CURL_LIBRARIES})
    target_link_libraries(shadowvm_static PRIVATE ${CURL_LIBRARIES})
endif()
