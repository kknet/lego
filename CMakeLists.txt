# option
option(BUILD_SHARED_LIBS "build shared library(.so/.a)" OFF)
option(BUILD_CLIENT "build lego client" OFF)

# version required
cmake_minimum_required(VERSION 2.8.12.2)
project(lego)

if(NOT BUILD_CLIENT)
    if(MSVC)
        set(CURL_LIBRARIES libcurl)
        set(CURL_INCLUDE_DIRS )
    else()
        #find_package(CURL REQUIRED)
    endif()
endif()


set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(BUILD_SHARED_LIBS)
    set(shared_str "shared")
else()
    set(shared_str "static")
endif()

message("build info: ${PROJECT_NAME}|${CMAKE_SYSTEM_NAME}|${CMAKE_BUILD_TYPE}|${shared_str}|lego")

# path definitions
set(DEP_DIR ${PROJECT_SOURCE_DIR}/third_party/depends)
set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(MAIN_DIR ${PROJECT_SOURCE_DIR}/src/main)

set(LINK_RT rt)
set(LINK_PTHREAD pthread)
set(LINK_ANDROID_LOG )
set(LINK_UUID )

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(LIB_DIR ${DEP_DIR}/libs/linux)
    set(LINK_UUID uuid)
    find_package(OpenSSL REQUIRED)
    include_directories(${OPENSSL_INCLUDE_DIR})
elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
    set(LIB_DIR ${DEP_DIR}/libs/android)
    set(LIB_DIR_XBASE ${XLEGOCOM_DIR}/third_party/xbase/libs/Android/release)
    set(LINK_RT )
    set(LINK_PTHREAD )
    set(LINK_ANDROID_LOG log)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    add_compile_options(-Wno-c++11-narrowing)
    set(LINK_RT )
    if(NOT DEFINED IOS_PLATFORM)
        set(LIB_DIR ${DEP_DIR}/libs/mac)
        set(LIB_DIR_XBASE ${XLEGOCOM_DIR}/third_party/xbase/libs/MacOS/release)
    else() # iOS
        message(STATUS "IOS_PLATFORM=${IOS_PLATFORM}")
        set(LIB_DIR ${DEP_DIR}/libs/ios)
        set(LIB_DIR_XBASE ${XLEGOCOM_DIR}/third_party/xbase/libs/iOS/release)
    endif()
    find_package(OpenSSL REQUIRED)
    include_directories(${OPENSSL_INCLUDE_DIR})
    find_library(CFLIB CoreFoundation)
    add_definitions(-DGUID_CFUUID)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(LINK_RT )
    set(LINK_PTHREAD )
    set(LIB_DIR ${DEP_DIR}/libs/win)
    set(LIB_DIR_XBASE ${XLEGOCOM_DIR}/third_party/xbase/libs/Windows/release)
else()
    message(FATAL "unsupported CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")
endif()

# include definitions
if(MSVC)
    include_directories(SYSTEM
        ${DEP_DIR}/include_win # for unofficial leveldb 1.18
    )
endif()
include_directories(SYSTEM
    ${DEP_DIR}/include
    ${DEP_DIR}/include/uv
    ${CURL_INCLUDE_DIRS} # for curl
)

# compile definitions
add_definitions(
    -DLEGO_TESTING # for testing
    -DOPENSSL_ROOT_DIR=/usr/local/Cellar/openssl/1.0.2r
    -DTEST_TRANSPORT_PERFOMANCE
    -DLEGO_TRACE_MESSAGE
)

add_compile_options(-fPIC)

if(MSVC)
    # set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")  # default: /MD
    add_definitions(-DNOMINMAX)  # enable std::min/std::max
    add_definitions(-D_CRT_SECURE_NO_WARNINGS) # disable strncpy -> strncpy_s warnings
    # add_compile_options(/Wall)  # too much warninngs
    # add_compile_options(/W4)  # default: /W3
    add_compile_options(/Zc:__cplusplus) # using correct __cplusplus value
    add_compile_options(/utf-8) # input/output as utf-8
    set(LINK_DL )
else()
    add_compile_options(-Wall -pthread)
    add_compile_options(-Wno-unused-variable)
	add_compile_options(-std=c++11) # cmake 2.8(default in centos 7) can't recognize 'CMAKE_CXX_STANDARD'
    set(LINK_DL dl)
endif()

# link definitions
link_directories(
    ${LIB_DIR}
)

# bin/lib
add_executable(lego ${MAIN_DIR}/main.cc)
add_executable(vpn_proxy ${MAIN_DIR}/vpn_proxy.cc)
add_executable(vpn_client ${MAIN_DIR}/vpn_client.cc)

set(LINK_ARGS
    services
    init
    root_congress
    client
    bft
    vss
    election
    network
    sync
    broadcast
    dht
    nat_traverse
    transport
    kcp
    bz2
    block
    db
    security
    statistics
    ip
    common
    protobuf
    uv
    pthread
    tcmalloc
    ${LINK_PTHREAD}
    ${LINK_DL}
    ${LINK_RT}
    ${LINK_ANDROID_LOG}
    ${CFLIB}
)


set(CLIENT_LINK_ARGS
    client
    init
    bft
    block
    statistics
    vss
    network
    sync
    broadcast
    dht
    nat_traverse
    transport
    kcp
    bz2
    db
    security
    json2pb
    ip
    common
    protobuf
    uv
    uuid
    pthread
    tcmalloc
    ${LINK_PTHREAD}
    ${LINK_DL}
    ${LINK_RT}
    ${LINK_ANDROID_LOG}
    ${CFLIB}
)

target_link_libraries(lego ${LINK_ARGS})
target_link_libraries(vpn_proxy ${LINK_ARGS})
target_link_libraries(vpn_client ${CLIENT_LINK_ARGS})

include_directories(SYSTEM ${SRC_DIR})

if(BUILD_CLIENT)
else()
    add_subdirectory(${SRC_DIR}/common common)
    add_subdirectory(${SRC_DIR}/ip ip)
#    add_subdirectory(${SRC_DIR}/uuid uuid)
    add_subdirectory(${SRC_DIR}/json2pb json2pb)
    add_subdirectory(${SRC_DIR}/security security)
    add_subdirectory(${SRC_DIR}/db db)
    add_subdirectory(${SRC_DIR}/block block)
    add_subdirectory(${SRC_DIR}/transport transport)
    add_subdirectory(${SRC_DIR}/dht dht)
    add_subdirectory(${SRC_DIR}/nat_traverse nat_traverse)
    add_subdirectory(${SRC_DIR}/broadcast broadcast)
    add_subdirectory(${SRC_DIR}/sync sync)
    add_subdirectory(${SRC_DIR}/network network)
    add_subdirectory(${SRC_DIR}/election election)
    add_subdirectory(${SRC_DIR}/bft bft)
    add_subdirectory(${SRC_DIR}/vss vss)
    add_subdirectory(${SRC_DIR}/init init)
    add_subdirectory(${SRC_DIR}/services services)
    add_subdirectory(${SRC_DIR}/client client)
    add_subdirectory(${SRC_DIR}/root_congress)
    add_subdirectory(${SRC_DIR}/statistics)

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_subdirectory(${SRC_DIR}/common/tests common_test)
        add_subdirectory(${SRC_DIR}/ip/tests ip_test)
        add_subdirectory(${SRC_DIR}/db/tests db_test)
        add_subdirectory(${SRC_DIR}/transport/demo udp_demo_svr)
        add_subdirectory(${SRC_DIR}/broadcast/tests broadcast_test )
        add_subdirectory(${SRC_DIR}/security/tests security_test )
        add_subdirectory(${SRC_DIR}/services/tests services_test)
    endif()
endif()
