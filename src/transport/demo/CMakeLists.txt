cmake_minimum_required(VERSION 3.8)

add_compile_options(-Wno-unused-parameter)

add_executable(udp_demo_svr server.cc)

add_dependencies(udp_demo_svr transport uv common protobuf pthread)
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(udp_demo_svr PRIVATE transport common uv pthread)
endif()
