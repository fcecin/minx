add_executable(startstop startstop.cpp)
target_compile_options(startstop PRIVATE -Wall -Wextra)
target_link_options(startstop PRIVATE "-Wl,-z,noexecstack")
target_link_libraries(startstop PRIVATE minxlib)

add_executable(startstop_harness harness.cpp)
target_compile_options(startstop_harness PRIVATE -Wall -Wextra)
target_link_options(startstop_harness PRIVATE "-Wl,-z,noexecstack")
