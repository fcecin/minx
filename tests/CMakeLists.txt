find_package(Boost 1.83.0 REQUIRED COMPONENTS unit_test_framework)

file(GLOB TEST_SOURCES CONFIGURE_DEPENDS "*.cpp")

add_executable(minxtests ${TEST_SOURCES})

target_link_libraries(minxtests
  PRIVATE
  minxlib
  Boost::unit_test_framework
)

add_test(NAME MinxTests COMMAND minxtests)
