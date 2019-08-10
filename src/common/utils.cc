#include "common/utils.h"

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

namespace lego {

namespace common {
    
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

std::string GetAccountAddress(const std::string& pubkey) {
    return common::Hash::Hash256(pubkey);
}

std::string CreateGID(const std::string& pubkey) {
    std::string str = (pubkey + Random::RandomString(1024u));
    return common::Hash::Hash256(str);
}

uint32_t RandomCountry() {
    return rand() % FX;
}

}  // namespace common

}  // namespace lego
