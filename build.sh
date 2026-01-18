#!/bin/bash

# Stop the script if any command fails
set -e

print_help() {
    echo "Builds the project, runs tests, or cleans build files."
    echo ""
    echo "Usage: $0 [target] [options] | [command]"
    echo ""
    echo "Targets (defaults to 'debug' if unspecified but flags are present):"
    echo "  debug           Builds with debug information, no optimizations."
    echo "  release         Builds for production (optimized, no debug info)."
    echo "  relwithdebinfo  Builds an optimized build with debug info."
    echo "  minsizerel      Builds the smallest possible release."
    echo ""
    echo "Options:"
    echo "  --asan          Enables AddressSanitizer."
    echo "  --test          Runs the unit tests after building."
    echo "  --clean         Cleans the target before building."
    echo "  --rm            Deletes 'build/' dir before building."
    echo "  --help, -h      Print help and exit."
    echo ""
    echo "Commands:"
    echo "  clean           Cleans ALL targets."
    echo "  rm              Deletes 'build/' dir."
    echo ""
    echo "Examples:"
    echo "  $0 --test --asan       Build debug with ASan and run tests"
    echo "  $0 release --clean     Rebuild (Clean + Build) release"
    echo "  $0 rm                  Wipe all builds"
}

deep_clean_project() {
    echo "--- DEEP Cleaning project (Removing 'build/' directory) ---"
    if [ -d "build" ]; then
        rm -rf build
        echo "✅ Deep Cleanup complete. 'build/' directory removed."
    else
        echo "ℹ️ 'build/' directory not found. Nothing to deep-clean."
    fi
}

soft_clean_project() {
    echo "--- SOFT Cleaning project (Removing compilation artifacts for ALL targets) ---"
    local BUILDS_CLEANED=0

    for BUILD_TYPE_LOWER in "release" "debug" "relwithdebinfo" "minsizerel"; do
        local BUILD_DIR="build/${BUILD_TYPE_LOWER}"
        if [ -d "${BUILD_DIR}" ]; then
            echo "-> Cleaning ${BUILD_TYPE_LOWER} configuration in ${BUILD_DIR}"
            cmake --build "${BUILD_DIR}" --target clean
            BUILDS_CLEANED=1
        fi
    done

    if [ "$BUILDS_CLEANED" -eq 0 ]; then
        echo "ℹ️ No build configurations found in 'build/'. Run a build first or use 'rm'."
    else
        echo "✅ Soft Cleanup complete."
    fi
}

clean_one_target() {
    local BUILD_TYPE_LOWER="$1"
    local BUILD_DIR="build/${BUILD_TYPE_LOWER}"

    if [ -d "${BUILD_DIR}" ]; then
        echo "--- Cleaning ${BUILD_TYPE_LOWER} target ---"
        cmake --build "${BUILD_DIR}" --target clean
        echo "✅ Cleaned ${BUILD_TYPE_LOWER}."
    else
        echo "ℹ️  Build directory '${BUILD_DIR}' does not exist. Skipping clean step."
    fi
}

build_one_config() {
    local BUILD_TYPE_LOWER="$1"
    local BUILD_TYPE_CAMEL="$2"
    local BUILD_DIR="build/${BUILD_TYPE_LOWER}"

    echo "--- Building for ${BUILD_TYPE_CAMEL} ---"

    local SANITIZE_FLAGS=""
    local LINKER_FLAGS=""

    if [ "$ENABLE_ASAN" = true ]; then
        echo "💉 Injecting AddressSanitizer flags..."
        SANITIZE_FLAGS="-fsanitize=address -fno-omit-frame-pointer"
        LINKER_FLAGS="-fsanitize=address"
    else
        SANITIZE_FLAGS=""
        LINKER_FLAGS=""
    fi

    local CMAKE_CMD=(
        cmake -S . -B "${BUILD_DIR}"
        -D CMAKE_BUILD_TYPE="${BUILD_TYPE_CAMEL}"
        "-DCMAKE_CXX_FLAGS=${SANITIZE_FLAGS}"
        "-DCMAKE_C_FLAGS=${SANITIZE_FLAGS}"
        "-DCMAKE_EXE_LINKER_FLAGS=${LINKER_FLAGS}"
        "-DCMAKE_MODULE_LINKER_FLAGS=${LINKER_FLAGS}"
        "-DCMAKE_SHARED_LINKER_FLAGS=${LINKER_FLAGS}"
    )

    # Configure
    "${CMAKE_CMD[@]}"

    # Build
    cmake --build "${BUILD_DIR}" -- -j8

    echo "✅ ${BUILD_TYPE_CAMEL} build complete."
}

run_tests() {
    local BUILD_TYPE_LOWER="$1"
    local TEST_DIR="build/${BUILD_TYPE_LOWER}/tests"

    echo "--- Running Tests for ${BUILD_TYPE_LOWER} ---"

    if [ ! -d "${TEST_DIR}" ]; then
        echo "❌ Test directory not found: ${TEST_DIR}"
        exit 1
    fi

    # Find the executable that identifies as a Boost.Test module
    local FOUND_BIN=""

    for f in "${TEST_DIR}"/*; do
        if [ -f "$f" ] && [ -x "$f" ] && [[ "$f" != *.sh ]]; then
            if "$f" --help 2>&1 | grep -q "Boost.Test"; then
                FOUND_BIN="$f"
                break
            fi
        fi
    done

    if [ -n "${FOUND_BIN}" ]; then
        echo "✅ Found Boost.Test binary: ${FOUND_BIN}"

        if [ "$ENABLE_ASAN" = true ]; then
            echo "👻 Running with AddressSanitizer enabled..."
        fi

        "${FOUND_BIN}" --log_level=test_suite --color_output=yes
    else
        echo "❌ No Boost.Test executable found in: ${TEST_DIR}"
        echo "   Make sure the build succeeded."
        exit 1
    fi
}

if [ "$#" -eq 0 ]; then
    print_help
    exit 0
fi

TARGET="debug"
CAMEL_TARGET="Debug"
ACTION="build"
RUN_TESTS=false
DO_CLEAN=false
ENABLE_ASAN=false
DO_DEEP_CLEAN=false

for arg in "$@"; do
    LOWER_ARG=$(echo "$arg" | tr '[:upper:]' '[:lower:]')

    case "$LOWER_ARG" in
        --help|-h)
            print_help
            exit 0
            ;;
        --test)
            RUN_TESTS=true
            ;;
        --clean)
            DO_CLEAN=true
            ;;
        --asan)
            ENABLE_ASAN=true
            ;;
        --rm)
            DO_DEEP_CLEAN=true
            ;;
        clean)
            ACTION="soft_clean_all"
            ;;
        rm)
            ACTION="deep_clean"
            ;;
        release)
            TARGET="release"
            CAMEL_TARGET="Release"
            ;;
        debug)
            TARGET="debug"
            CAMEL_TARGET="Debug"
            ;;
        relwithdebinfo)
            TARGET="relwithdebinfo"
            CAMEL_TARGET="RelWithDebInfo"
            ;;
        minsizerel)
            TARGET="minsizerel"
            CAMEL_TARGET="MinSizeRel"
            ;;
        *)
            print_help
            echo ""
            echo "❌ Error: Invalid argument '$arg'." >&2
            exit 1
            ;;
    esac
done

case "$ACTION" in
    deep_clean)
        deep_clean_project
        exit 0
        ;;
    soft_clean_all)
        soft_clean_project
        exit 0
        ;;
    build)
        if [ "$DO_DEEP_CLEAN" = true ]; then
            deep_clean_project
        fi

        if [ "$DO_CLEAN" = true ]; then
            clean_one_target "$TARGET"
        fi

        build_one_config "$TARGET" "$CAMEL_TARGET"

        if [ "$RUN_TESTS" = true ]; then
            run_tests "$TARGET"
        fi
        ;;
esac

echo ""
echo "Done."