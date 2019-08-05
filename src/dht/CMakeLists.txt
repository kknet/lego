cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ dht_src)
aux_source_directory(./proto proto_src)
add_library(dht STATIC ${dht_src} ${proto_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(dht PRIVATE nat_traverse transport common uv protobuf log4cpp )
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(dht PRIVATE gcov)
    endif()
endif()

