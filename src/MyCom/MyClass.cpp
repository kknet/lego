// MyClass.cpp: CMyClass 的实现

#include "stdafx.h"
#include "MyClass.h"
#include <iostream>
#include "vpn_client.h"
using namespace std;

STDMETHODIMP CMyClass::TotalSum(LONG n, LONG* sum) {
    lego::client::VpnClient::Instance();
    int i;
    *sum = 0;
    if (n < 0) {
        cout << "invalid input" << endl;
    }

    for (i = 0; i < n; ++i) {
        *sum += i;
    }
    return S_OK;
}
// CMyClass

