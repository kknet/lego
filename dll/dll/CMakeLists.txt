cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ common_src)
aux_source_directory(./tick tick_src)
add_library(common SHARED ${common_src} ${tick_src})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(common PRIVATE uuid ssl crypto log4cpp xxhash)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(common PRIVATE gcov)
    endif()
endif()

