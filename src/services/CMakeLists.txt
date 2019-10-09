cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ services_src)
aux_source_directory(./proto proto_src)
aux_source_directory(./vpn_server vpn_server_src)
aux_source_directory(./vpn_route vpn_route_serc)
aux_source_directory(./vpn_svr_proxy vpn_svr_proxy_src)
add_library(services STATIC ${services_src} ${proto_src} ${vpn_route_serc}  ${vpn_server_src} ${vpn_svr_proxy_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(services PRIVATE init vss bft vss network dht transport security block db common shadowsocks-libev ipset mbedtls mbedcrypto sodium bloom cares ev pcre uv protobuf log4cpp pthread )
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(services PRIVATE gcov)
    endif()
endif()

