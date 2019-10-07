cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ statistics_src)
add_library(statistics SHARED ${statistics_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(statistics PRIVATE common uuid log4cpp xxhash)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(statistics PRIVATE gcov)
    endif()
endif()

