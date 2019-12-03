cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ transport_src)
aux_source_directory(./udp udp_transport_src)
aux_source_directory(./http http_transport_src)
aux_source_directory(./proto proto_src)
aux_source_directory(./rudp rudp_src)
add_library(transport STATIC ${rudp_src} ${transport_src} ${udp_transport_src} ${http_transport_src}  ${proto_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(transport PRIVATE statistics common kcp uv protobuf log4cpp pthread)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(transport PRIVATE gcov)
    endif()
endif()

