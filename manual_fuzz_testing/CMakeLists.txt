cmake_minimum_required(VERSION 3.10)

project(YaraFuzzer)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 11)

# Use Clang as the compiler (if not already set)
set(CMAKE_CXX_COMPILER "clang++")
set(CMAKE_C_COMPILER "clang")

# Enable sanitizer flags for fuzzing
add_compile_options(-fsanitize=fuzzer -fsanitize=address)

# Use PkgConfig to find YARA
find_package(PkgConfig REQUIRED)
pkg_check_modules(YARA REQUIRED yara)

# Include YARA header files
include_directories(${YARA_INCLUDE_DIRS})

# Link directories for YARA
link_directories(${YARA_LIBRARY_DIRS})

# Add the fuzz target source file
add_executable(fuzz_target fuzz_target.cc)

# Link the fuzz target with YARA and libFuzzer
target_link_libraries(fuzz_target ${YARA_LIBRARIES} -fsanitize=fuzzer -fsanitize=address)
