// client_dll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "vpn_client.h"

int init_network() {
    lego::client::VpnClient::Instance();
    return 0;
}