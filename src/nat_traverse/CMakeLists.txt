cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ nat_traverse_src)
aux_source_directory(./proto proto_src)
add_library(nat_traverse STATIC ${nat_traverse_src} ${proto_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(nat_traverse PRIVATE dht transport common uv protobuf log4cpp )
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(nat_traverse PRIVATE gcov)
    endif()
endif()

