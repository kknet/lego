cmake_minimum_required(VERSION 3.8)

aux_source_directory(./ json2pb_src)
add_library(json2pb SHARED ${json2pb_src} )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(json2pb PRIVATE jansson)
    if (XENABLE_CODE_COVERAGE)
        target_link_libraries(json2pb PRIVATE gcov)
    endif()
endif()

