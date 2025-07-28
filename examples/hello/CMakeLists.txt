add_executable(hello hello.cpp)

target_link_options(hello PRIVATE "-Wl,-z,noexecstack")

target_link_libraries(hello PRIVATE minxlib)
