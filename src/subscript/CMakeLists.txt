cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ subscript_src)
add_library(subscript STATIC ${subscript_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(subscript PRIVATE gcov)
    endif()
endif()

