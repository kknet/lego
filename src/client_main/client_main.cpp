#include <iostream>
#include <thread>
#include <windows.h>

#include "dll_interface.h"

int main(int argc, char** argv) {
    auto int_res = init_network(
            "10.7.17.41",
            18993,
            "id:122.112.234.133:9001,id:119.3.15.76:9001,id:119.3.73.78:9001",
            "D://conf/lego.conf",
            "D://log/lego.log",
            "D://conf/log4cpp.properties");
    if (int_res == "ERROR") {
        std::cout << "init client failed: " << int_res << std::endl;
        system("pause");
        return 1;
    }
    std::cout << "init network success.: " << int_res << std::endl;
    use_cmd();
    return 0;
}
