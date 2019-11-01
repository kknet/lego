cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ limit_src)
add_library(limit STATIC ${limit_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(limit PRIVATE common )
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(limit PRIVATE gcov)
    endif()
endif()

