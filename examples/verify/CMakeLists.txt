add_executable(verify verify.cpp)

target_link_options(verify PRIVATE "-Wl,-z,noexecstack")

target_link_libraries(verify PRIVATE minxlib)
