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

set(SVM_OBF_HEADER ${CMAKE_CURRENT_BINARY_DIR}/generated/obf_strings.h)
set(SVM_OBF_CMAKE ${CMAKE_CURRENT_BINARY_DIR}/generated/obf_soname.cmake)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
execute_process(
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen_obf_strings.py ${SVM_OBF_HEADER} ${SVM_OBF_CMAKE}
    RESULT_VARIABLE _svm_obf_rc
)
if(NOT _svm_obf_rc EQUAL 0)
    message(FATAL_ERROR "gen_obf_strings.py failed")
endif()
include(${SVM_OBF_CMAKE})
add_custom_target(shadowvm_obf_gen DEPENDS ${SVM_OBF_HEADER})

file(GLOB SHADOWVM_SOURCES "src/*.c")

add_library(shadowvm SHARED ${SHADOWVM_SOURCES})
add_dependencies(shadowvm shadowvm_obf_gen)
set_target_properties(shadowvm PROPERTIES NO_SONAME TRUE)
target_include_directories(shadowvm PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_include_directories(shadowvm PUBLIC include)
target_include_directories(shadowvm PRIVATE src)
target_link_options(shadowvm PRIVATE
    -Wl,-z,now -Wl,-z,relro
    -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/src/svm.map
    -Wl,-soname,${SVM_OBF_SONAME}
)

add_library(shadowvm_static STATIC ${SHADOWVM_SOURCES})
add_dependencies(shadowvm_static shadowvm_obf_gen)
target_include_directories(shadowvm_static PUBLIC include)
target_include_directories(shadowvm_static PRIVATE src ${CMAKE_CURRENT_BINARY_DIR}/generated)
