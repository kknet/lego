cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ block_src)
aux_source_directory(./proto proto_src)
add_library(block STATIC ${block_src} ${proto_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(block PRIVATE db common log4cpp leveldb)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(block PRIVATE gcov)
    endif()
endif()

