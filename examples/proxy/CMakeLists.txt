add_executable(minxproxy proxy.cpp)

target_compile_options(minxproxy PRIVATE -Wall -Wextra)

target_link_options(minxproxy PRIVATE "-Wl,-z,noexecstack")

target_link_libraries(minxproxy PRIVATE minxlib)
