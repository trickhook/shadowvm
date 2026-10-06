cmake_minimum_required(VERSION 3.22)
project(jni_hello C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_compile_options(
    -Wall -Wextra -Wno-unused-parameter
    -fvisibility=hidden
    -ffunction-sections -fdata-sections
    -O2 -fno-stack-protector
)
add_link_options(-Wl,--gc-sections -Wl,--strip-all)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/../../vm ${CMAKE_CURRENT_BINARY_DIR}/vm)

add_library(jni_hello SHARED src/jni_hello.c)
target_include_directories(jni_hello PRIVATE src)
target_link_libraries(jni_hello PRIVATE shadowvm_static log)

set_target_properties(jni_hello PROPERTIES
    LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_LIST_DIR}/src/jni_hello.map"
)

add_executable(smoke src/smoke.c)
target_include_directories(smoke PRIVATE src)
target_link_libraries(smoke PRIVATE shadowvm_static)
