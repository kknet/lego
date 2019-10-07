cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ uuid_src)
add_library(uuid SHARED ${uuid_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(uuid PRIVATE pthread)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(uuid PRIVATE gcov)
    endif()
endif()

