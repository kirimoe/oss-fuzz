# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/kanra/oss-fuzz/manual_libfuzz_test

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/kanra/oss-fuzz/manual_libfuzz_test

# Include any dependencies generated for this target.
include CMakeFiles/fuzz_test_code.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/fuzz_test_code.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/fuzz_test_code.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/fuzz_test_code.dir/flags.make

CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.o: CMakeFiles/fuzz_test_code.dir/flags.make
CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.o: fuzz_test_code.cc
CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.o: CMakeFiles/fuzz_test_code.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/kanra/oss-fuzz/manual_libfuzz_test/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.o -MF CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.o.d -o CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.o -c /home/kanra/oss-fuzz/manual_libfuzz_test/fuzz_test_code.cc

CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/kanra/oss-fuzz/manual_libfuzz_test/fuzz_test_code.cc > CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.i

CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/kanra/oss-fuzz/manual_libfuzz_test/fuzz_test_code.cc -o CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.s

# Object files for target fuzz_test_code
fuzz_test_code_OBJECTS = \
"CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.o"

# External object files for target fuzz_test_code
fuzz_test_code_EXTERNAL_OBJECTS =

fuzz_test_code: CMakeFiles/fuzz_test_code.dir/fuzz_test_code.cc.o
fuzz_test_code: CMakeFiles/fuzz_test_code.dir/build.make
fuzz_test_code: CMakeFiles/fuzz_test_code.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/kanra/oss-fuzz/manual_libfuzz_test/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable fuzz_test_code"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/fuzz_test_code.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/fuzz_test_code.dir/build: fuzz_test_code
.PHONY : CMakeFiles/fuzz_test_code.dir/build

CMakeFiles/fuzz_test_code.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/fuzz_test_code.dir/cmake_clean.cmake
.PHONY : CMakeFiles/fuzz_test_code.dir/clean

CMakeFiles/fuzz_test_code.dir/depend:
	cd /home/kanra/oss-fuzz/manual_libfuzz_test && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/kanra/oss-fuzz/manual_libfuzz_test /home/kanra/oss-fuzz/manual_libfuzz_test /home/kanra/oss-fuzz/manual_libfuzz_test /home/kanra/oss-fuzz/manual_libfuzz_test /home/kanra/oss-fuzz/manual_libfuzz_test/CMakeFiles/fuzz_test_code.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/fuzz_test_code.dir/depend

