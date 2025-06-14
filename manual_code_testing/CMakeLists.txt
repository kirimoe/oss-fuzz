cmake_minimum_required(VERSION 3.5)
project(yara_stream_example CXX)

set(CMAKE_CXX_STANDARD 11)  # or 14/17 if you prefer

find_library(YARA_LIB yara)
find_path(YARA_INCLUDE_DIR yara.h)

if(NOT YARA_LIB OR NOT YARA_INCLUDE_DIR)
    message(FATAL_ERROR "YARA library or headers not found. Please install YARA development files.")
endif()

include_directories(${YARA_INCLUDE_DIR})

add_executable(fuzz_test_code fuzz_test_code.cc)

target_link_libraries(fuzz_test_code ${YARA_LIB})
