# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.19

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
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/haoxin/disk-dut/research/github/dead_instrumenter

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/haoxin/disk-dut/research/github/dead_instrumenter/build

# Include any dependencies generated for this target.
include src/tool/CMakeFiles/dead-instrument.dir/depend.make

# Include the progress variables for this target.
include src/tool/CMakeFiles/dead-instrument.dir/progress.make

# Include the compile flags for this target's objects.
include src/tool/CMakeFiles/dead-instrument.dir/flags.make

src/tool/CMakeFiles/dead-instrument.dir/DeadInstrument.cpp.o: src/tool/CMakeFiles/dead-instrument.dir/flags.make
src/tool/CMakeFiles/dead-instrument.dir/DeadInstrument.cpp.o: ../src/tool/DeadInstrument.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/haoxin/disk-dut/research/github/dead_instrumenter/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/tool/CMakeFiles/dead-instrument.dir/DeadInstrument.cpp.o"
	cd /home/haoxin/disk-dut/research/github/dead_instrumenter/build/src/tool && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/dead-instrument.dir/DeadInstrument.cpp.o -c /home/haoxin/disk-dut/research/github/dead_instrumenter/src/tool/DeadInstrument.cpp

src/tool/CMakeFiles/dead-instrument.dir/DeadInstrument.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/dead-instrument.dir/DeadInstrument.cpp.i"
	cd /home/haoxin/disk-dut/research/github/dead_instrumenter/build/src/tool && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/haoxin/disk-dut/research/github/dead_instrumenter/src/tool/DeadInstrument.cpp > CMakeFiles/dead-instrument.dir/DeadInstrument.cpp.i

src/tool/CMakeFiles/dead-instrument.dir/DeadInstrument.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/dead-instrument.dir/DeadInstrument.cpp.s"
	cd /home/haoxin/disk-dut/research/github/dead_instrumenter/build/src/tool && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/haoxin/disk-dut/research/github/dead_instrumenter/src/tool/DeadInstrument.cpp -o CMakeFiles/dead-instrument.dir/DeadInstrument.cpp.s

# Object files for target dead-instrument
dead__instrument_OBJECTS = \
"CMakeFiles/dead-instrument.dir/DeadInstrument.cpp.o"

# External object files for target dead-instrument
dead__instrument_EXTERNAL_OBJECTS =

bin/dead-instrument: src/tool/CMakeFiles/dead-instrument.dir/DeadInstrument.cpp.o
bin/dead-instrument: src/tool/CMakeFiles/dead-instrument.dir/build.make
bin/dead-instrument: src/libDeadInstrumentlib.a
bin/dead-instrument: src/tool/CMakeFiles/dead-instrument.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/haoxin/disk-dut/research/github/dead_instrumenter/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ../../bin/dead-instrument"
	cd /home/haoxin/disk-dut/research/github/dead_instrumenter/build/src/tool && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/dead-instrument.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/tool/CMakeFiles/dead-instrument.dir/build: bin/dead-instrument

.PHONY : src/tool/CMakeFiles/dead-instrument.dir/build

src/tool/CMakeFiles/dead-instrument.dir/clean:
	cd /home/haoxin/disk-dut/research/github/dead_instrumenter/build/src/tool && $(CMAKE_COMMAND) -P CMakeFiles/dead-instrument.dir/cmake_clean.cmake
.PHONY : src/tool/CMakeFiles/dead-instrument.dir/clean

src/tool/CMakeFiles/dead-instrument.dir/depend:
	cd /home/haoxin/disk-dut/research/github/dead_instrumenter/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/haoxin/disk-dut/research/github/dead_instrumenter /home/haoxin/disk-dut/research/github/dead_instrumenter/src/tool /home/haoxin/disk-dut/research/github/dead_instrumenter/build /home/haoxin/disk-dut/research/github/dead_instrumenter/build/src/tool /home/haoxin/disk-dut/research/github/dead_instrumenter/build/src/tool/CMakeFiles/dead-instrument.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/tool/CMakeFiles/dead-instrument.dir/depend

