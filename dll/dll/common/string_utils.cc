#include "stdafx.h"
#include "common/string_utils.h"

#include <errno.h>
#include <string.h>

#include <exception>
#include <limits>
#include <memory>

#ifndef LONG_MIN
#define LONG_MIN std::numeric_limits<long>::min()  // NOLINT
#endif

#undef min
#undef max

namespace lego {

namespace common {

static long long LongLong(const char* s) {  // NOLINT
    if (!s) {
        throw ConvertException("ERROR: not end of str.");
    }
    errno = 0;
    char* end_ptr;
    long long res = strtoll(s, &end_ptr, 0);  // NOLINT
    switch (errno) {
    case 0:
        if (end_ptr == s || *end_ptr != '\0') {
            throw ConvertException("ERROR: not end of str.");
        }
        return res;
    case ERANGE:
        if (res == LONG_MIN) {
            throw ConvertException("ERROR: invalid num.");
        } else {
            throw ConvertException("ERROR: invalid num.");
        }
    default:
        throw ConvertException("ERROR: invalid num.");
    }
}

static unsigned long long UnsignedLongLong(const char* s) {  // NOLINT
    if (!s) {
        throw ConvertException("ERROR: not end of str.");
    }
    errno = 0;
    char* end_ptr;
    unsigned long long res = strtoull(s, &end_ptr, 0);  // NOLINT

    if (memchr(s, '-', end_ptr - s) != NULL) {
        throw ConvertException("ERROR: not end of str.");
    }

    switch (errno) {
    case 0:
        if (end_ptr == s || *end_ptr != '\0') {
            throw ConvertException("ERROR: not end of str.");
        }
        return res;
    case ERANGE:
        if (res == static_cast<uint64_t>(LONG_MIN)) {
            throw ConvertException("ERROR: invalid num.");
        } else {
            throw ConvertException("ERROR: invalid num.");
        }
    default:
        throw ConvertException("ERROR: invalid num.");
    }
}

static float Float(const char* s) {
    if (!s) {
        throw ConvertException("ERROR: not end of str.");
    }
    errno = 0;
    char* end_ptr;
#if __GNUC__ <= 2
    float res = float(strtod(s, &end_ptr));  // NOLINT
#else
    float res = strtof(s, &end_ptr);
#endif
    switch (errno) {
    case 0:
        if (end_ptr == s || *end_ptr != '\0') {
            throw ConvertException("ERROR: not end of str.");
        }
        return res;
    case ERANGE:
        if (res == LONG_MIN) {
            throw ConvertException("ERROR: invalid num.");
        } else {
            throw ConvertException("ERROR: invalid num.");
        }
    default:
        throw ConvertException("ERROR: invalid num.");
    }
}

static double Double(const char* s) {
    if (!s) {
        throw ConvertException("ERROR: not end of str.");
    }
    errno = 0;
    char* end_ptr;
    double res = strtod(s, &end_ptr);

    switch (errno) {
    case 0:
        if (end_ptr == s || *end_ptr != '\0') {
            throw ConvertException("ERROR: not end of str.");
        }
        return res;
    case ERANGE:
        if (res == LONG_MIN) {
            throw ConvertException("ERROR: invalid num.");
        } else {
            throw ConvertException("ERROR: invalid num.");
        }
    default:
        throw ConvertException("ERROR: invalid num.");
    }
}

static long double LongDouble(const char* s) {  // NOLINT
    if (!s) {
        throw ConvertException("ERROR: not end of str.");
    }
    errno = 0;
    char* end_ptr;
#if __GNUC__ <= 2
    long double res = strtod(s, &end_ptr);  // NOLINT
#else
    long double res = strtold(s, &end_ptr);  // NOLINT
#endif

    switch (errno) {
    case 0:
        if (end_ptr == s || *end_ptr != '\0') {
            throw ConvertException("ERROR: not end of str.");
        }
        return res;
    case ERANGE:
        if (res == LONG_MIN) {
            throw ConvertException("ERROR: invalid num.");
        } else {
            throw ConvertException("ERROR: invalid num.");
        }
    default:
        throw ConvertException("ERROR: invalid num.");
    }
}

template<typename T>
T SignedCheckCastValue(const std::string& str) {
    auto val = LongLong(str.c_str());
    if (val < std::numeric_limits<T>::min()) {
        throw ConvertException("value bound error[type min]");
    }

    if (val > std::numeric_limits<T>::max()) {
        throw ConvertException("value bound error[type max]");
    }
    return static_cast<T>(val);
}

template<typename T>
T SignedCheckCastValue(const char* str) {
    auto val = LongLong(str);
    if (val < std::numeric_limits<T>::min()) {
        throw ConvertException("value bound error[type min]");
    }

    if (val > std::numeric_limits<T>::max()) {
        throw ConvertException("value bound error[type max]");
    }
    return static_cast<T>(val);
}

bool StringUtil::ToBool(const char* str) {
    return SignedCheckCastValue<bool>(str);
}

bool StringUtil::ToBool(const std::string& str) {
    return SignedCheckCastValue<bool>(str);
}

int8_t StringUtil::ToInt8(const char* str) {
    return SignedCheckCastValue<int8_t>(str);
}

int16_t StringUtil::ToInt16(const char* str) {
    return SignedCheckCastValue<int16_t>(str);
}

int32_t StringUtil::ToInt32(const char* str) {
    return SignedCheckCastValue<int32_t>(str);
}

int64_t StringUtil::ToInt64(const char* str) {
    return LongLong(str);
}

int8_t StringUtil::ToInt8(const std::string& str) {
    return SignedCheckCastValue<int8_t>(str);
}

int16_t StringUtil::ToInt16(const std::string& str) {
    return SignedCheckCastValue<int16_t>(str);
}

int32_t StringUtil::ToInt32(const std::string& str) {
    return SignedCheckCastValue<int32_t>(str);
}

int64_t StringUtil::ToInt64(const std::string& str) {
    return LongLong(str.c_str());
}

template<typename T>
T UnsignedCheckCastValue(const std::string& str) {
    auto val = LongLong(str.c_str());
    if (val < 0) {
        throw ConvertException("value bound error[0L]");
    }

    if (val > std::numeric_limits<T>::max()) {
        throw ConvertException("value bound error[uint16_t max]");
    }
    return static_cast<T>(val);
}

template<typename T>
T UnsignedCheckCastValue(const char* str) {
    auto val = LongLong(str);
    if (val < 0) {
        throw ConvertException("value bound error[0L]");
    }

    if (val > std::numeric_limits<T>::max()) {
        throw ConvertException("value bound error[uint16_t max]");
    }
    return static_cast<T>(val);
}

uint8_t StringUtil::ToUint8(const char* str) {
    return UnsignedCheckCastValue<uint8_t>(str);
}

uint16_t StringUtil::ToUint16(const char* str) {
    return UnsignedCheckCastValue<uint16_t>(str);
}

uint32_t StringUtil::ToUint32(const char* str) {
    return UnsignedCheckCastValue<uint32_t>(str);
}

uint64_t StringUtil::ToUint64(const char* str) {
    return UnsignedLongLong(str);
}

uint8_t StringUtil::ToUint8(const std::string& str) {
    return UnsignedCheckCastValue<uint8_t>(str);
}

uint16_t StringUtil::ToUint16(const std::string& str) {
    return UnsignedCheckCastValue<uint16_t>(str);
}

uint32_t StringUtil::ToUint32(const std::string& str) {
    return UnsignedCheckCastValue<uint32_t>(str);
}

uint64_t StringUtil::ToUint64(const std::string& str) {
    return UnsignedLongLong(str.c_str());
}

float StringUtil::ToFloat(const char* str) {
    return Float(str);
}

double StringUtil::ToDouble(const char* str) {
    return Double(str);
}

float StringUtil::ToFloat(const std::string& str) {
    return Float(str.c_str());
}

double StringUtil::ToDouble(const std::string& str) {
    return Double(str.c_str());
}

bool StringUtil::IsNumeric(const char* str) {
    try {
        LongDouble(str);
    } catch (...) {
        return false;
    }
    return true;
}

bool StringUtil::IsNumeric(const std::string& str) {
    try {
        LongDouble(str.c_str());
    } catch (...) {
        return false;
    }
    return true;
}

void StringUtil::Trim(std::string& str) {
    if (str.empty()) {
        return;
    }
    str.erase(0, str.find_first_not_of(" "));
    str.erase(str.find_last_not_of(" ") + 1);
    str.erase(0, str.find_first_not_of("\t"));
    str.erase(str.find_last_not_of("\t") + 1);
    str.erase(0, str.find_first_not_of("\n"));
    str.erase(str.find_last_not_of("\n") + 1);

}

}  // namespace common

}  // namespace lego
