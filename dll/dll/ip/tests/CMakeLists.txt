cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

aux_source_directory(./ ip_test_src)
add_executable(ip_test ${ip_test_src})

add_dependencies(ip_test ip)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(ip_test PRIVATE ip common gtest gtest_main gmock gmock_main pthread dl)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(ip_test PRIVATE ip gtest gtest_main gmock gmock_main)
endif()
