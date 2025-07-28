#!/bin/bash
#
# Builds the project for a specified configuration.
#
# Arguments:
#   release | debug | relwithdebinfo | minsizerel
#

# Stop the script if any command fails
set -e

# --- Reusable function to print usage instructions ---
print_help() {
  echo "Usage: $0 [release|debug|relwithdebinfo|minsizerel]"
  echo "  - release:        Builds for production (optimized, no debug info)."
  echo "  - debug:          Builds with debug information, no optimizations."
  echo "  - relwithdebinfo: Builds an optimized build with debug info."
  echo "  - minsizerel:     Builds the smallest possible release."
}

# --- Reusable function to build a specific configuration ---
# Argument 1: The build type in lowercase (e.g., "release")
# Argument 2: The build type in CMake's format (e.g., "Release")
build_one_config() {
  local BUILD_TYPE_LOWER="$1"
  local BUILD_TYPE_CAMEL="$2"
  local BUILD_DIR="build/${BUILD_TYPE_LOWER}"

  echo "--- Building for ${BUILD_TYPE_CAMEL} ---"

  # Configure using CMake
  # -S .: Source directory is the current directory.
  # -B ${BUILD_DIR}: Build directory is build/<type>.
  cmake -S . -B "${BUILD_DIR}" -D CMAKE_BUILD_TYPE="${BUILD_TYPE_CAMEL}"

  # Build the project using the generated build system
  # The -- -j8 passes the -j8 flag to the underlying 'make' command.
  cmake --build "${BUILD_DIR}" -- -j8

  echo "✅ ${BUILD_TYPE_CAMEL} build complete. Library is at: ${BUILD_DIR}/libminx.a"
}

# --- Main script logic ---

# If no arguments are provided, print help and exit.
if [ "$#" -eq 0 ]; then
  print_help
  exit 0
fi

# Convert the first argument to lowercase for case-insensitive matching.
ARG_LOWER=$(echo "$1" | tr '[:upper:]' '[:lower:]')
BUILD_TYPE_CAMEL=""

# Determine the correct CMake build type string based on the input.
case "$ARG_LOWER" in
  release)
    BUILD_TYPE_CAMEL="Release"
    ;;
  debug)
    BUILD_TYPE_CAMEL="Debug"
    ;;
  relwithdebinfo)
    BUILD_TYPE_CAMEL="RelWithDebInfo"
    ;;
  minsizerel)
    BUILD_TYPE_CAMEL="MinSizeRel"
    ;;
  *)
    echo "Error: Invalid build type '$1'." >&2
    echo ""
    print_help
    exit 1
    ;;
esac

# Proceed with the build for the specified configuration.
build_one_config "$ARG_LOWER" "$BUILD_TYPE_CAMEL"

echo "" # Add a blank line for readability
echo "Build is complete."
