cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ root_congress_src)
add_library(root_congress SHARED ${root_congress_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(root_congress PRIVATE init vss bft vss network dht transport security block db common uv protobuf log4cpp pthread )
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(root_congress PRIVATE gcov)
    endif()
endif()

