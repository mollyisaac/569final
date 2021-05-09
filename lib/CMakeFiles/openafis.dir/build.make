# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
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
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/fuzzusers/openafis

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/fuzzusers/openafis

# Include any dependencies generated for this target.
include lib/CMakeFiles/openafis.dir/depend.make

# Include the progress variables for this target.
include lib/CMakeFiles/openafis.dir/progress.make

# Include the compile flags for this target's objects.
include lib/CMakeFiles/openafis.dir/flags.make

lib/CMakeFiles/openafis.dir/FastMath.cpp.o: lib/CMakeFiles/openafis.dir/flags.make
lib/CMakeFiles/openafis.dir/FastMath.cpp.o: lib/FastMath.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/fuzzusers/openafis/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object lib/CMakeFiles/openafis.dir/FastMath.cpp.o"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/openafis.dir/FastMath.cpp.o -c /home/fuzzusers/openafis/lib/FastMath.cpp

lib/CMakeFiles/openafis.dir/FastMath.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/openafis.dir/FastMath.cpp.i"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/fuzzusers/openafis/lib/FastMath.cpp > CMakeFiles/openafis.dir/FastMath.cpp.i

lib/CMakeFiles/openafis.dir/FastMath.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/openafis.dir/FastMath.cpp.s"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/fuzzusers/openafis/lib/FastMath.cpp -o CMakeFiles/openafis.dir/FastMath.cpp.s

lib/CMakeFiles/openafis.dir/FastMath.cpp.o.requires:

.PHONY : lib/CMakeFiles/openafis.dir/FastMath.cpp.o.requires

lib/CMakeFiles/openafis.dir/FastMath.cpp.o.provides: lib/CMakeFiles/openafis.dir/FastMath.cpp.o.requires
	$(MAKE) -f lib/CMakeFiles/openafis.dir/build.make lib/CMakeFiles/openafis.dir/FastMath.cpp.o.provides.build
.PHONY : lib/CMakeFiles/openafis.dir/FastMath.cpp.o.provides

lib/CMakeFiles/openafis.dir/FastMath.cpp.o.provides.build: lib/CMakeFiles/openafis.dir/FastMath.cpp.o


lib/CMakeFiles/openafis.dir/Match.cpp.o: lib/CMakeFiles/openafis.dir/flags.make
lib/CMakeFiles/openafis.dir/Match.cpp.o: lib/Match.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/fuzzusers/openafis/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object lib/CMakeFiles/openafis.dir/Match.cpp.o"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/openafis.dir/Match.cpp.o -c /home/fuzzusers/openafis/lib/Match.cpp

lib/CMakeFiles/openafis.dir/Match.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/openafis.dir/Match.cpp.i"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/fuzzusers/openafis/lib/Match.cpp > CMakeFiles/openafis.dir/Match.cpp.i

lib/CMakeFiles/openafis.dir/Match.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/openafis.dir/Match.cpp.s"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/fuzzusers/openafis/lib/Match.cpp -o CMakeFiles/openafis.dir/Match.cpp.s

lib/CMakeFiles/openafis.dir/Match.cpp.o.requires:

.PHONY : lib/CMakeFiles/openafis.dir/Match.cpp.o.requires

lib/CMakeFiles/openafis.dir/Match.cpp.o.provides: lib/CMakeFiles/openafis.dir/Match.cpp.o.requires
	$(MAKE) -f lib/CMakeFiles/openafis.dir/build.make lib/CMakeFiles/openafis.dir/Match.cpp.o.provides.build
.PHONY : lib/CMakeFiles/openafis.dir/Match.cpp.o.provides

lib/CMakeFiles/openafis.dir/Match.cpp.o.provides.build: lib/CMakeFiles/openafis.dir/Match.cpp.o


lib/CMakeFiles/openafis.dir/MatchMany.cpp.o: lib/CMakeFiles/openafis.dir/flags.make
lib/CMakeFiles/openafis.dir/MatchMany.cpp.o: lib/MatchMany.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/fuzzusers/openafis/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object lib/CMakeFiles/openafis.dir/MatchMany.cpp.o"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/openafis.dir/MatchMany.cpp.o -c /home/fuzzusers/openafis/lib/MatchMany.cpp

lib/CMakeFiles/openafis.dir/MatchMany.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/openafis.dir/MatchMany.cpp.i"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/fuzzusers/openafis/lib/MatchMany.cpp > CMakeFiles/openafis.dir/MatchMany.cpp.i

lib/CMakeFiles/openafis.dir/MatchMany.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/openafis.dir/MatchMany.cpp.s"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/fuzzusers/openafis/lib/MatchMany.cpp -o CMakeFiles/openafis.dir/MatchMany.cpp.s

lib/CMakeFiles/openafis.dir/MatchMany.cpp.o.requires:

.PHONY : lib/CMakeFiles/openafis.dir/MatchMany.cpp.o.requires

lib/CMakeFiles/openafis.dir/MatchMany.cpp.o.provides: lib/CMakeFiles/openafis.dir/MatchMany.cpp.o.requires
	$(MAKE) -f lib/CMakeFiles/openafis.dir/build.make lib/CMakeFiles/openafis.dir/MatchMany.cpp.o.provides.build
.PHONY : lib/CMakeFiles/openafis.dir/MatchMany.cpp.o.provides

lib/CMakeFiles/openafis.dir/MatchMany.cpp.o.provides.build: lib/CMakeFiles/openafis.dir/MatchMany.cpp.o


lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.o: lib/CMakeFiles/openafis.dir/flags.make
lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.o: lib/OpenAFIS.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/fuzzusers/openafis/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.o"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/openafis.dir/OpenAFIS.cpp.o -c /home/fuzzusers/openafis/lib/OpenAFIS.cpp

lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/openafis.dir/OpenAFIS.cpp.i"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/fuzzusers/openafis/lib/OpenAFIS.cpp > CMakeFiles/openafis.dir/OpenAFIS.cpp.i

lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/openafis.dir/OpenAFIS.cpp.s"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/fuzzusers/openafis/lib/OpenAFIS.cpp -o CMakeFiles/openafis.dir/OpenAFIS.cpp.s

lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.o.requires:

.PHONY : lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.o.requires

lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.o.provides: lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.o.requires
	$(MAKE) -f lib/CMakeFiles/openafis.dir/build.make lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.o.provides.build
.PHONY : lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.o.provides

lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.o.provides.build: lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.o


lib/CMakeFiles/openafis.dir/Render.cpp.o: lib/CMakeFiles/openafis.dir/flags.make
lib/CMakeFiles/openafis.dir/Render.cpp.o: lib/Render.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/fuzzusers/openafis/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object lib/CMakeFiles/openafis.dir/Render.cpp.o"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/openafis.dir/Render.cpp.o -c /home/fuzzusers/openafis/lib/Render.cpp

lib/CMakeFiles/openafis.dir/Render.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/openafis.dir/Render.cpp.i"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/fuzzusers/openafis/lib/Render.cpp > CMakeFiles/openafis.dir/Render.cpp.i

lib/CMakeFiles/openafis.dir/Render.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/openafis.dir/Render.cpp.s"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/fuzzusers/openafis/lib/Render.cpp -o CMakeFiles/openafis.dir/Render.cpp.s

lib/CMakeFiles/openafis.dir/Render.cpp.o.requires:

.PHONY : lib/CMakeFiles/openafis.dir/Render.cpp.o.requires

lib/CMakeFiles/openafis.dir/Render.cpp.o.provides: lib/CMakeFiles/openafis.dir/Render.cpp.o.requires
	$(MAKE) -f lib/CMakeFiles/openafis.dir/build.make lib/CMakeFiles/openafis.dir/Render.cpp.o.provides.build
.PHONY : lib/CMakeFiles/openafis.dir/Render.cpp.o.provides

lib/CMakeFiles/openafis.dir/Render.cpp.o.provides.build: lib/CMakeFiles/openafis.dir/Render.cpp.o


lib/CMakeFiles/openafis.dir/Template.cpp.o: lib/CMakeFiles/openafis.dir/flags.make
lib/CMakeFiles/openafis.dir/Template.cpp.o: lib/Template.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/fuzzusers/openafis/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object lib/CMakeFiles/openafis.dir/Template.cpp.o"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/openafis.dir/Template.cpp.o -c /home/fuzzusers/openafis/lib/Template.cpp

lib/CMakeFiles/openafis.dir/Template.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/openafis.dir/Template.cpp.i"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/fuzzusers/openafis/lib/Template.cpp > CMakeFiles/openafis.dir/Template.cpp.i

lib/CMakeFiles/openafis.dir/Template.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/openafis.dir/Template.cpp.s"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/fuzzusers/openafis/lib/Template.cpp -o CMakeFiles/openafis.dir/Template.cpp.s

lib/CMakeFiles/openafis.dir/Template.cpp.o.requires:

.PHONY : lib/CMakeFiles/openafis.dir/Template.cpp.o.requires

lib/CMakeFiles/openafis.dir/Template.cpp.o.provides: lib/CMakeFiles/openafis.dir/Template.cpp.o.requires
	$(MAKE) -f lib/CMakeFiles/openafis.dir/build.make lib/CMakeFiles/openafis.dir/Template.cpp.o.provides.build
.PHONY : lib/CMakeFiles/openafis.dir/Template.cpp.o.provides

lib/CMakeFiles/openafis.dir/Template.cpp.o.provides.build: lib/CMakeFiles/openafis.dir/Template.cpp.o


lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.o: lib/CMakeFiles/openafis.dir/flags.make
lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.o: lib/TemplateCSV.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/fuzzusers/openafis/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.o"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/openafis.dir/TemplateCSV.cpp.o -c /home/fuzzusers/openafis/lib/TemplateCSV.cpp

lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/openafis.dir/TemplateCSV.cpp.i"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/fuzzusers/openafis/lib/TemplateCSV.cpp > CMakeFiles/openafis.dir/TemplateCSV.cpp.i

lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/openafis.dir/TemplateCSV.cpp.s"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/fuzzusers/openafis/lib/TemplateCSV.cpp -o CMakeFiles/openafis.dir/TemplateCSV.cpp.s

lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.o.requires:

.PHONY : lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.o.requires

lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.o.provides: lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.o.requires
	$(MAKE) -f lib/CMakeFiles/openafis.dir/build.make lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.o.provides.build
.PHONY : lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.o.provides

lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.o.provides.build: lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.o


lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o: lib/CMakeFiles/openafis.dir/flags.make
lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o: lib/TemplateISO19794_2_2005.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/fuzzusers/openafis/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o -c /home/fuzzusers/openafis/lib/TemplateISO19794_2_2005.cpp

lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.i"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/fuzzusers/openafis/lib/TemplateISO19794_2_2005.cpp > CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.i

lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.s"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/fuzzusers/openafis/lib/TemplateISO19794_2_2005.cpp -o CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.s

lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o.requires:

.PHONY : lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o.requires

lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o.provides: lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o.requires
	$(MAKE) -f lib/CMakeFiles/openafis.dir/build.make lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o.provides.build
.PHONY : lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o.provides

lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o.provides.build: lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o


lib/CMakeFiles/openafis.dir/Triplet.cpp.o: lib/CMakeFiles/openafis.dir/flags.make
lib/CMakeFiles/openafis.dir/Triplet.cpp.o: lib/Triplet.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/fuzzusers/openafis/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Building CXX object lib/CMakeFiles/openafis.dir/Triplet.cpp.o"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/openafis.dir/Triplet.cpp.o -c /home/fuzzusers/openafis/lib/Triplet.cpp

lib/CMakeFiles/openafis.dir/Triplet.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/openafis.dir/Triplet.cpp.i"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/fuzzusers/openafis/lib/Triplet.cpp > CMakeFiles/openafis.dir/Triplet.cpp.i

lib/CMakeFiles/openafis.dir/Triplet.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/openafis.dir/Triplet.cpp.s"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/fuzzusers/openafis/lib/Triplet.cpp -o CMakeFiles/openafis.dir/Triplet.cpp.s

lib/CMakeFiles/openafis.dir/Triplet.cpp.o.requires:

.PHONY : lib/CMakeFiles/openafis.dir/Triplet.cpp.o.requires

lib/CMakeFiles/openafis.dir/Triplet.cpp.o.provides: lib/CMakeFiles/openafis.dir/Triplet.cpp.o.requires
	$(MAKE) -f lib/CMakeFiles/openafis.dir/build.make lib/CMakeFiles/openafis.dir/Triplet.cpp.o.provides.build
.PHONY : lib/CMakeFiles/openafis.dir/Triplet.cpp.o.provides

lib/CMakeFiles/openafis.dir/Triplet.cpp.o.provides.build: lib/CMakeFiles/openafis.dir/Triplet.cpp.o


lib/CMakeFiles/openafis.dir/TripletScalar.cpp.o: lib/CMakeFiles/openafis.dir/flags.make
lib/CMakeFiles/openafis.dir/TripletScalar.cpp.o: lib/TripletScalar.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/fuzzusers/openafis/CMakeFiles --progress-num=$(CMAKE_PROGRESS_10) "Building CXX object lib/CMakeFiles/openafis.dir/TripletScalar.cpp.o"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/openafis.dir/TripletScalar.cpp.o -c /home/fuzzusers/openafis/lib/TripletScalar.cpp

lib/CMakeFiles/openafis.dir/TripletScalar.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/openafis.dir/TripletScalar.cpp.i"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/fuzzusers/openafis/lib/TripletScalar.cpp > CMakeFiles/openafis.dir/TripletScalar.cpp.i

lib/CMakeFiles/openafis.dir/TripletScalar.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/openafis.dir/TripletScalar.cpp.s"
	cd /home/fuzzusers/openafis/lib && /usr/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/fuzzusers/openafis/lib/TripletScalar.cpp -o CMakeFiles/openafis.dir/TripletScalar.cpp.s

lib/CMakeFiles/openafis.dir/TripletScalar.cpp.o.requires:

.PHONY : lib/CMakeFiles/openafis.dir/TripletScalar.cpp.o.requires

lib/CMakeFiles/openafis.dir/TripletScalar.cpp.o.provides: lib/CMakeFiles/openafis.dir/TripletScalar.cpp.o.requires
	$(MAKE) -f lib/CMakeFiles/openafis.dir/build.make lib/CMakeFiles/openafis.dir/TripletScalar.cpp.o.provides.build
.PHONY : lib/CMakeFiles/openafis.dir/TripletScalar.cpp.o.provides

lib/CMakeFiles/openafis.dir/TripletScalar.cpp.o.provides.build: lib/CMakeFiles/openafis.dir/TripletScalar.cpp.o


# Object files for target openafis
openafis_OBJECTS = \
"CMakeFiles/openafis.dir/FastMath.cpp.o" \
"CMakeFiles/openafis.dir/Match.cpp.o" \
"CMakeFiles/openafis.dir/MatchMany.cpp.o" \
"CMakeFiles/openafis.dir/OpenAFIS.cpp.o" \
"CMakeFiles/openafis.dir/Render.cpp.o" \
"CMakeFiles/openafis.dir/Template.cpp.o" \
"CMakeFiles/openafis.dir/TemplateCSV.cpp.o" \
"CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o" \
"CMakeFiles/openafis.dir/Triplet.cpp.o" \
"CMakeFiles/openafis.dir/TripletScalar.cpp.o"

# External object files for target openafis
openafis_EXTERNAL_OBJECTS =

lib/libopenafis.a: lib/CMakeFiles/openafis.dir/FastMath.cpp.o
lib/libopenafis.a: lib/CMakeFiles/openafis.dir/Match.cpp.o
lib/libopenafis.a: lib/CMakeFiles/openafis.dir/MatchMany.cpp.o
lib/libopenafis.a: lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.o
lib/libopenafis.a: lib/CMakeFiles/openafis.dir/Render.cpp.o
lib/libopenafis.a: lib/CMakeFiles/openafis.dir/Template.cpp.o
lib/libopenafis.a: lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.o
lib/libopenafis.a: lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o
lib/libopenafis.a: lib/CMakeFiles/openafis.dir/Triplet.cpp.o
lib/libopenafis.a: lib/CMakeFiles/openafis.dir/TripletScalar.cpp.o
lib/libopenafis.a: lib/CMakeFiles/openafis.dir/build.make
lib/libopenafis.a: lib/CMakeFiles/openafis.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/fuzzusers/openafis/CMakeFiles --progress-num=$(CMAKE_PROGRESS_11) "Linking CXX static library libopenafis.a"
	cd /home/fuzzusers/openafis/lib && $(CMAKE_COMMAND) -P CMakeFiles/openafis.dir/cmake_clean_target.cmake
	cd /home/fuzzusers/openafis/lib && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/openafis.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
lib/CMakeFiles/openafis.dir/build: lib/libopenafis.a

.PHONY : lib/CMakeFiles/openafis.dir/build

lib/CMakeFiles/openafis.dir/requires: lib/CMakeFiles/openafis.dir/FastMath.cpp.o.requires
lib/CMakeFiles/openafis.dir/requires: lib/CMakeFiles/openafis.dir/Match.cpp.o.requires
lib/CMakeFiles/openafis.dir/requires: lib/CMakeFiles/openafis.dir/MatchMany.cpp.o.requires
lib/CMakeFiles/openafis.dir/requires: lib/CMakeFiles/openafis.dir/OpenAFIS.cpp.o.requires
lib/CMakeFiles/openafis.dir/requires: lib/CMakeFiles/openafis.dir/Render.cpp.o.requires
lib/CMakeFiles/openafis.dir/requires: lib/CMakeFiles/openafis.dir/Template.cpp.o.requires
lib/CMakeFiles/openafis.dir/requires: lib/CMakeFiles/openafis.dir/TemplateCSV.cpp.o.requires
lib/CMakeFiles/openafis.dir/requires: lib/CMakeFiles/openafis.dir/TemplateISO19794_2_2005.cpp.o.requires
lib/CMakeFiles/openafis.dir/requires: lib/CMakeFiles/openafis.dir/Triplet.cpp.o.requires
lib/CMakeFiles/openafis.dir/requires: lib/CMakeFiles/openafis.dir/TripletScalar.cpp.o.requires

.PHONY : lib/CMakeFiles/openafis.dir/requires

lib/CMakeFiles/openafis.dir/clean:
	cd /home/fuzzusers/openafis/lib && $(CMAKE_COMMAND) -P CMakeFiles/openafis.dir/cmake_clean.cmake
.PHONY : lib/CMakeFiles/openafis.dir/clean

lib/CMakeFiles/openafis.dir/depend:
	cd /home/fuzzusers/openafis && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/fuzzusers/openafis /home/fuzzusers/openafis/lib /home/fuzzusers/openafis /home/fuzzusers/openafis/lib /home/fuzzusers/openafis/lib/CMakeFiles/openafis.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : lib/CMakeFiles/openafis.dir/depend

