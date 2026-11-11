#include "common/logging.h"
#include <chrono>
#include <iomanip>
#include <mutex>

namespace Scarlett {

static std::mutex g_logMutex;

void Logger::Log(LogLevel level, const std::string& subsystem, const std::string& message) {
    std::lock_guard<std::mutex> lock(g_logMutex);

    const char* colorCode = "\033[0m";
    const char* levelStr = "INFO";

    switch (level) {
        case LogLevel::Debug:
            colorCode = "\033[36m"; // Cyan
            levelStr = "DEBUG";
            break;
        case LogLevel::Info:
            colorCode = "\033[32m"; // Green
            levelStr = "INFO";
            break;
        case LogLevel::Warning:
            colorCode = "\033[33m"; // Yellow
            levelStr = "WARN";
            break;
        case LogLevel::Error:
            colorCode = "\033[31m"; // Red
            levelStr = "ERROR";
            break;
        case LogLevel::Critical:
            colorCode = "\033[1;31m"; // Bold Red
            levelStr = "FATAL";
            break;
    }

    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm tm_buf;
    localtime_r(&now_time_t, &tm_buf);

    std::cout << "\033[90m[" 
              << std::put_time(&tm_buf, "%H:%M:%S") << "." 
              << std::setfill('0') << std::setw(3) << ms.count() 
              << "]\033[0m "
              << colorCode << "[" << levelStr << "]\033[0m "
              << "\033[35m[" << subsystem << "]\033[0m "
              << message << "\n";
}

} // namespace Scarlett
