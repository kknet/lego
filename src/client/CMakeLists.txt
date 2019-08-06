cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ client_src)
add_library(client STATIC ${client_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(client PRIVATE network dht transport security block db common uv protobuf log4cpp pthread )
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(client PRIVATE gcov)
    endif()
endif()

