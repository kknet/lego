#include "common/utils.h"

#include <signal.h>
#include <atomic>
#include <cstdint>
#include <mutex>

#ifdef _WIN32
#include <winsock2.h>
#include <time.h>
#else
#include <sys/time.h>
#endif

#ifdef _MSC_VER
#define _WINSOCKAPI_
#include <windows.h>
#endif

#include "uuid/uuid.h"
#include "common/hash.h"
#include "common/random.h"
#include "common/country_code.h"
#include "common/global_info.h"
#include "common/time_utils.h"

namespace lego {

namespace common {
    
volatile bool global_stop = false;

uint64_t TimeStampMsec() {
#ifdef _WIN32
    struct timeval tv;
    time_t clock;
    struct tm tm;
    SYSTEMTIME wtm;

    GetLocalTime(&wtm);
    tm.tm_year = wtm.wYear - 1900;
    tm.tm_mon = wtm.wMonth - 1;
    tm.tm_mday = wtm.wDay;
    tm.tm_hour = wtm.wHour;
    tm.tm_min = wtm.wMinute;
    tm.tm_sec = wtm.wSecond;
    tm.tm_isdst = -1;
    clock = mktime(&tm);
    tv.tv_sec = clock;
    tv.tv_usec = wtm.wMilliseconds * 1000;
    return ((uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000);
#else
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return ((uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000);
#endif
}

uint64_t TimeStampUsec() {
#ifdef _WIN32
    struct timeval tv;
    time_t clock;
    struct tm tm;
    SYSTEMTIME wtm;

    GetLocalTime(&wtm);
    tm.tm_year = wtm.wYear - 1900;
    tm.tm_mon = wtm.wMonth - 1;
    tm.tm_mday = wtm.wDay;
    tm.tm_hour = wtm.wHour;
    tm.tm_min = wtm.wMinute;
    tm.tm_sec = wtm.wSecond;
    tm.tm_isdst = -1;
    clock = mktime(&tm);
    tv.tv_sec = clock;
    tv.tv_usec = wtm.wMilliseconds * 1000;
    return ((uint64_t)tv.tv_sec * 1000 * 1000 + (uint64_t)tv.tv_usec);
#else
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return ((uint64_t)tv.tv_sec * 1000 * 1000 + (uint64_t)tv.tv_usec);
#endif
}

uint32_t GetPoolIndex(const std::string& acc_addr) {
    uint32_t pool_index = common::Hash::Hash32(acc_addr);
    pool_index %= kImmutablePoolSize;
    return pool_index;
}

std::string CreateGID(const std::string& pubkey) {
    std::string str = (pubkey + Random::RandomString(1024u));
    return common::Hash::Hash256(str);
}

uint32_t RandomCountry() {
    return rand() % FX;
}

void itimeofday(long *sec, long *usec) {
#ifndef WIN32
	struct timeval time;
	gettimeofday(&time, NULL);
	if (sec) *sec = time.tv_sec;
	if (usec) *usec = time.tv_usec;
#else
	static long mode = 0, addsec = 0;
	BOOL retval;
	static int64_t freq = 1;
	int64_t qpc;
	if (mode == 0) {
		retval = QueryPerformanceFrequency((LARGE_INTEGER*)&freq);
		freq = (freq == 0) ? 1 : freq;
		retval = QueryPerformanceCounter((LARGE_INTEGER*)&qpc);
		addsec = (long)time(NULL);
		addsec = addsec - (long)((qpc / freq) & 0x7fffffff);
		mode = 1;
	}
	retval = QueryPerformanceCounter((LARGE_INTEGER*)&qpc);
	retval = retval * 2;
	if (sec) *sec = (long)(qpc / freq) + addsec;
	if (usec) *usec = (long)((qpc % freq) * 1000000 / freq);
#endif
}

int64_t iclock64(void) {
	long s, u;
	int64_t value;
	itimeofday(&s, &u);
	value = ((int64_t)s) * 1000 + (u / 1000);
	return value;
}

uint32_t iclock() {
	return static_cast<uint32_t>(iclock64() & 0xfffffffful);
}

static void SignalCallback(int sig_int) {
    global_stop = true;
}

void SignalRegister() {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
    signal(SIGINT, SignalCallback);
    signal(SIGTERM, SignalCallback);
}

uint16_t GetVpnServerPort(const std::string& dht_key, uint32_t timestamp_days) {
    std::string tmp_str = dht_key + std::to_string(timestamp_days);
    uint32_t hash32 = common::Hash::Hash32(tmp_str);
    uint32_t vpn_server_range = kVpnServerPortRangeMax - kVpnServerPortRangeMin;
    uint16_t tmp_port = (hash32 % vpn_server_range) + kVpnServerPortRangeMin;
    return tmp_port;
}

uint16_t GetVpnRoutePort(const std::string& dht_key, uint32_t timestamp_days) {
    std::string tmp_str = dht_key + std::to_string(timestamp_days);
    uint32_t hash32 = common::Hash::Hash32(tmp_str);
    uint32_t vpn_route_range = kVpnRoutePortRangeMax - kVpnRoutePortRangeMin;
    uint16_t tmp_port = (hash32 % vpn_route_range) + kVpnRoutePortRangeMin;
    return tmp_port;
}

}  // namespace common

}  // namespace lego
