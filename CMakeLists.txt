# This CMake project will only produce the build/libminx.a static library.
# examples/ and tests/ have their own build system that depends on this.

cmake_minimum_required(VERSION 3.21)

project(minx)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(FetchContent)

# If no network connection, just use cached FetchContent deps
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

# Threads

find_package(Threads)

# Boost (from system)

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.83.0 REQUIRED COMPONENTS system log log_setup)

# RandomX (librandomx.a)

FetchContent_Declare(
    randomx
    GIT_REPOSITORY https://github.com/tevador/RandomX.git
    GIT_TAG        master
)

# This tells RandomX to compile with optimizations for the current machine's CPU.
# Comment the line below if you need portable binaries.
set(ARCH "native" CACHE STRING "Set RandomX architecture optimizations" FORCE)

FetchContent_MakeAvailable(randomx)

# logkv

FetchContent_Declare(
    logkv
    GIT_REPOSITORY https://github.com/fcecin/logkv.git
    GIT_TAG        main
)

FetchContent_MakeAvailable(logkv)

# minx lib (libminx.a)

file(GLOB CORE_CPP "src/*.cpp")

add_library(minxlib STATIC ${CORE_CPP})

target_compile_definitions(minxlib PRIVATE BOOST_ASIO_HEADER_ONLY)

target_include_directories(minxlib
PUBLIC
  ${randomx_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${Boost_INCLUDE_DIRS}
)

target_link_libraries(minxlib
PUBLIC
  logkv
  randomx
  ${Boost_LIBRARIES}
PRIVATE
  Threads::Threads
)

set_target_properties(minxlib PROPERTIES OUTPUT_NAME "minx")

# minx examples

option(MINX_BUILD_EXAMPLES "Build examples" ON)

if(MINX_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

# minx tests

option(MINX_BUILD_TESTS "Build unit tests" ON)

if(MINX_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
