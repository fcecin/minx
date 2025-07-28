# This CMake project will only produce the build/libminx.a static library.
# examples/ have their own build system that depends on this.

# This is the minimum CMake version for cryptopp-cmake. Ubuntu 24.04 has CMake 3.28.3.
cmake_minimum_required(VERSION 3.21)

project(minx)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(FetchContent)

# Threads

find_package(Threads)

# Boost (from system)

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.83.0 REQUIRED COMPONENTS chrono filesystem program_options system thread nowide)

# Crypto++ via cryptopp-cmake
# This just builds whatever is the most recent Crypto++ release according to cryptopp-cmake master.
# There is no good reason to ever use anything other than the newest Crypto++ available, but if there
# is some problem, just change the GIT_TAG below to use a specific version of cryptopp-cmake.

FetchContent_Declare(
  cryptopp-cmake
  GIT_REPOSITORY https://github.com/abdes/cryptopp-cmake.git
  GIT_TAG        master
)

set(CRYPTOPP_BUILD_TESTING OFF CACHE BOOL "Disable building Crypto++ tests" FORCE)

FetchContent_MakeAvailable(cryptopp-cmake)

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

# fcecin/logkv (a header-only library)

FetchContent_Declare(
    logkv
    GIT_REPOSITORY https://github.com/fcecin/logkv.git
    GIT_TAG        main
)

FetchContent_MakeAvailable(logkv)

# minx lib (libminx.a)

file(GLOB CORE_CPP "src/*.cpp")

add_library(minxlib STATIC ${CORE_CPP})

target_include_directories(minxlib
PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${Boost_INCLUDE_DIRS}
  ${cryptopp-cmake_SOURCE_DIR}/cryptopp
  ${randomx_SOURCE_DIR}/src
  ${logkv_SOURCE_DIR}/include
)

target_link_libraries(minxlib
PUBLIC
  ${Boost_LIBRARIES}
  Threads::Threads
  cryptopp::cryptopp
  randomx
)

set_target_properties(minxlib PROPERTIES OUTPUT_NAME "minx")

# minx examples

option(MINX_BUILD_EXAMPLES "Build examples" ON)

if(MINX_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
