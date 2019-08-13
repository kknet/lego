cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ transport_src)
aux_source_directory(./udp udp_transport_src)
aux_source_directory(./http http_transport_src)
aux_source_directory(./proto proto_src)
add_library(transport STATIC ${transport_src} ${udp_transport_src} ${http_transport_src}  ${proto_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(transport PRIVATE common uv protobuf log4cpp )
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(transport PRIVATE gcov)
    endif()
endif()

