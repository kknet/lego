cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ services_test_src)
add_executable(services_test ${services_test_src})

add_dependencies(services_test services)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(services_test PRIVATE services init vss bft vss network dht transport security block db common uv protobuf log4cpp pthread gtest gtest_main gmock gmock_main pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(services_test PRIVATE services gtest gtest_main gmock gmock_main)
endif()
