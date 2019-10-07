#pragma once

#include <string>
#include <memory>

#include "common/utils.h"

namespace lego {

namespace common {

class ConvertException : public std::exception {
public:
    ConvertException() : err_message_("ERROR: convert string to number failed!") {}
    explicit ConvertException(const std::string& err) : err_message_(err) {}
    virtual char const* what() const noexcept { return err_message_.c_str(); }

private:
    std::string err_message_;
};

class StringUtil {
public:
    static void Trim(std::string& str);
    static bool ToBool(const char* str);
    static int8_t ToInt8(const char* str);
    static int16_t ToInt16(const char* str);
    static int32_t ToInt32(const char* str);
    static int64_t ToInt64(const char* str);
    static uint8_t ToUint8(const char* str);
    static uint16_t ToUint16(const char* str);
    static uint32_t ToUint32(const char* str);
    static uint64_t ToUint64(const char* str);
    static float ToFloat(const char* str);
    static double ToDouble(const char* str);
    static bool IsNumeric(const char* str);

    static bool ToBool(const std::string& str);
    static int8_t ToInt8(const std::string& str);
    static int16_t ToInt16(const std::string& str);
    static int32_t ToInt32(const std::string& str);
    static int64_t ToInt64(const std::string& str);
    static uint8_t ToUint8(const std::string& str);
    static uint16_t ToUint16(const std::string& str);
    static uint32_t ToUint32(const std::string& str);
    static uint64_t ToUint64(const std::string& str);
    static float ToFloat(const std::string& str);
    static double ToDouble(const std::string& str);
    static bool IsNumeric(const std::string& str);

    template<typename ... Args>
    static std::string Format(const std::string& format, Args ... args) {
        size_t size = ::snprintf(nullptr, 0, format.c_str(), args ...) + 1;
        std::unique_ptr<char[]> buf(new char[size]);
        ::snprintf(buf.get(), size, format.c_str(), args ...);
        return std::string(buf.get(), buf.get() + size - 1);
    }

private:
    StringUtil() {}
    ~StringUtil() {}

    DISALLOW_COPY_AND_ASSIGN(StringUtil);
};

}

}
