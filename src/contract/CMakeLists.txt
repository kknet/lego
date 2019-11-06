cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ contract_src)
add_library(contract STATIC ${contract_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(contract PRIVATE common log4cpp xxhash)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(contract PRIVATE gcov)
    endif()
endif()

