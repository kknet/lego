# CMake generated Testfile for 
# Source directory: /root/lego/third_party/libuv-1.30.1
# Build directory: /root/lego/third_party/libuv-1.30.1/cbuild
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(uv_test "/root/lego/third_party/libuv-1.30.1/cbuild/uv_run_tests")
set_tests_properties(uv_test PROPERTIES  WORKING_DIRECTORY "/root/lego/third_party/libuv-1.30.1")
add_test(uv_test_a "/root/lego/third_party/libuv-1.30.1/cbuild/uv_run_tests_a")
set_tests_properties(uv_test_a PROPERTIES  WORKING_DIRECTORY "/root/lego/third_party/libuv-1.30.1")
