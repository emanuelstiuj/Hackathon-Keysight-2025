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
CMAKE_SOURCE_DIR = /challenge

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /challenge/build

# Utility rule file for run.

# Include any custom commands dependencies for this target.
include src/CMakeFiles/run.dir/compiler_depend.make

# Include the progress variables for this target.
include src/CMakeFiles/run.dir/progress.make

src/CMakeFiles/run:
	cd /challenge/build/src && ./gpu-router

run: src/CMakeFiles/run
run: src/CMakeFiles/run.dir/build.make
.PHONY : run

# Rule to build all files generated by this target.
src/CMakeFiles/run.dir/build: run
.PHONY : src/CMakeFiles/run.dir/build

src/CMakeFiles/run.dir/clean:
	cd /challenge/build/src && $(CMAKE_COMMAND) -P CMakeFiles/run.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/run.dir/clean

src/CMakeFiles/run.dir/depend:
	cd /challenge/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /challenge /challenge/src /challenge/build /challenge/build/src /challenge/build/src/CMakeFiles/run.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : src/CMakeFiles/run.dir/depend

