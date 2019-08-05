cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ security_src)
add_library(security STATIC ${security_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(security PRIVATE ssl crypto secp256k1 uuid log4cpp xxhash)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(security PRIVATE gcov)
    endif()
endif()

