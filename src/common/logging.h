#pragma once

#include <iostream>
#include <string>
#include <sstream>

namespace Scarlett {

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical
};

class Logger {
public:
    static void Log(LogLevel level, const std::string& subsystem, const std::string& message);
};

#define LOG_DEBUG(subsys, msg)   ::Scarlett::Logger::Log(::Scarlett::LogLevel::Debug, subsys, msg)
#define LOG_INFO(subsys, msg)    ::Scarlett::Logger::Log(::Scarlett::LogLevel::Info, subsys, msg)
#define LOG_WARN(subsys, msg)    ::Scarlett::Logger::Log(::Scarlett::LogLevel::Warning, subsys, msg)
#define LOG_ERROR(subsys, msg)   ::Scarlett::Logger::Log(::Scarlett::LogLevel::Error, subsys, msg)
#define LOG_FATAL(subsys, msg)   ::Scarlett::Logger::Log(::Scarlett::LogLevel::Critical, subsys, msg)

} // namespace Scarlett
