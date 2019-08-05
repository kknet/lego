#pragma once

#include <string.h>

#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Priority.hh"
#include "log4cpp/PropertyConfigurator.hh"

#ifdef _WIN32
#define LEGO_LOG_FILE_NAME strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__
#else
#define LEGO_LOG_FILE_NAME strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__
#endif

#define LOG_INS log4cpp::Category::getInstance(std::string("sub1"))
#ifdef _WIN32
#define DEBUG(fmt, ...)  do {\
        LOG_INS.debug("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define INFO(fmt, ...)  do {\
        LOG_INS.info("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define WARN(fmt, ...)  do {\
        LOG_INS.warn("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define ERROR(fmt, ...)  do {\
        LOG_INS.error("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)
#else
#define DEBUG(fmt, ...)  do {\
        LOG_INS.debug("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define INFO(fmt, ...)  do {\
        LOG_INS.info("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define WARN(fmt, ...)  do {\
        LOG_INS.warn("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#define ERROR(fmt, ...)  do {\
        LOG_INS.error("[%s][%s][%d] " fmt, LEGO_LOG_FILE_NAME, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
} while (0)

#endif // _WIN32

#ifdef LOG
#undef LOG
#endif // LOG
#define LOG(level) LOG_INS << level << "[" << LEGO_LOG_FILE_NAME << ": " << __LINE__ << "]" 
