# CMAKE generated file: DO NOT EDIT!
# Generated by "NMake Makefiles" Generator, CMake Version 3.15

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

!IF "$(OS)" == "Windows_NT"
NULL=
!ELSE
NULL=nul
!ENDIF
SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = "C:\Program Files (x86)\CMake\bin\cmake.exe"

# The command to remove a file.
RM = "C:\Program Files (x86)\CMake\bin\cmake.exe" -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = D:\lego\lego\third_party\libuv

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = D:\lego\lego\third_party\libuv\cbuild_windows

# Utility rule file for Continuous.

# Include the progress variables for this target.
include CMakeFiles\Continuous.dir\progress.make

CMakeFiles\Continuous:
	echo >nul && "C:\Program Files (x86)\CMake\bin\ctest.exe" -D Continuous

Continuous: CMakeFiles\Continuous
Continuous: CMakeFiles\Continuous.dir\build.make

.PHONY : Continuous

# Rule to build all files generated by this target.
CMakeFiles\Continuous.dir\build: Continuous

.PHONY : CMakeFiles\Continuous.dir\build

CMakeFiles\Continuous.dir\clean:
	$(CMAKE_COMMAND) -P CMakeFiles\Continuous.dir\cmake_clean.cmake
.PHONY : CMakeFiles\Continuous.dir\clean

CMakeFiles\Continuous.dir\depend:
	$(CMAKE_COMMAND) -E cmake_depends "NMake Makefiles" D:\lego\lego\third_party\libuv D:\lego\lego\third_party\libuv D:\lego\lego\third_party\libuv\cbuild_windows D:\lego\lego\third_party\libuv\cbuild_windows D:\lego\lego\third_party\libuv\cbuild_windows\CMakeFiles\Continuous.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles\Continuous.dir\depend
