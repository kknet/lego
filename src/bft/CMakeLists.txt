cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ bft_src)
aux_source_directory(./proto proto_src)
aux_source_directory(./basic_bft/transaction transaction_src)
aux_source_directory(./basic_bft/transaction/proto transaction_proto_src)
add_library(bft SHARED ${bft_src} ${proto_src} ${transaction_src} ${transaction_proto_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(bft PRIVATE election network broadcast dht transport common uv protobuf log4cpp )
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(bft PRIVATE gcov)
    endif()
endif()

