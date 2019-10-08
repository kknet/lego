cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ init_src)
add_library(init STATIC ${init_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(init PRIVATE election network dht transport common uv protobuf log4cpp )
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(init PRIVATE gcov)
    endif()
endif()

