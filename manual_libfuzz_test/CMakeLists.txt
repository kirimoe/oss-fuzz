# Minimum version of CMake required.
# Use 3.10 or higher for modern CMake features like target_link_libraries(PRIVATE ...).
cmake_minimum_required(VERSION 3.10)

# Define your project.
# Set the project name and specify the language.
project(YaraFuzzerTest CXX)

# Specify the C++ standard to use (e.g., C++11 or newer).
# YARA library often requires C++11 or C++14 features implicitly or explicitly.
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF) # Ensure standard compliance, avoiding GNU extensions unless explicitly needed.

# Set compiler flags for AddressSanitizer and UndefinedBehaviorSanitizer.
# These flags instruct clang (or g++) to insert runtime checks for memory errors
# and undefined behavior, which will produce detailed "fancy errors" if detected.
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    set(SANITIZER_FLAGS "-fsanitize=address,undefined")
    # Add sanitizer flags to the compiler flags for C++
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SANITIZER_FLAGS}")
    # Add sanitizer flags to the linker flags to link the sanitizer runtime libraries
    set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} ${SANITIZER_FLAGS}")
endif()

# Find the YARA library.
# CMake will look for libyara and its associated header files.
# If YARA is installed in a non-standard location, you might need
# to set CMAKE_PREFIX_PATH or YARA_ROOT environment variables,
# or provide hints to cmake like:
# find_package(YARA REQUIRED HINTS /path/to/yara/install)
# 'REQUIRED' ensures that CMake will fail if YARA is not found.
#find_package(YARA REQUIRED HINTS ../manual_fuzz_testing/yara/)

# Use PkgConfig to find YARA
find_package(PkgConfig REQUIRED)
pkg_check_modules(YARA REQUIRED yara)

# Include YARA header files
include_directories(${YARA_INCLUDE_DIRS})

# Link directories for YARA
link_directories(${YARA_LIBRARY_DIRS})

# Add the executable target.
# This assumes your C++ source file is named 'fuzz_test_code.cc'.
# Ensure this matches the name of your source file containing the main function.
add_executable(fuzz_test_code fuzz_test_code.cc)

# Link the YARA library to your executable.
# target_link_libraries automatically adds necessary include directories
# that were found by find_package(YARA).
# Using YARA::yara is the modern, recommended way when using find_package.
target_link_libraries(fuzz_test_code PRIVATE ${YARA_LIBRARIES})

# target_link_libraries(fuzz_target ${YARA_LIBRARIES} -fsanitize=fuzzer -fsanitize=address)


# Optional: If you want to explicitly set clang as the compiler,
# you can uncomment these lines. However, if clang is in your PATH
# and configured as the default CXX compiler, CMake will pick it up automatically.
# set(CMAKE_CXX_COMPILER "clang++")
# set(CMAKE_C_COMPILER "clang")
