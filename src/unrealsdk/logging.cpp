#include "unrealsdk/pch.h"

#include "unrealsdk/env.h"
#include "unrealsdk/logging.h"
#include "unrealsdk/unrealsdk.h"
#include "unrealsdk/utils.h"

namespace unrealsdk::logging {

namespace {

std::mutex mutex{};

std::atomic<Level> unreal_console_level = Level::DEFAULT_CONSOLE_LEVEL;
HANDLE external_console_handle = nullptr;
std::unique_ptr<std::ostream> log_file_stream;

std::vector<log_callback> all_log_callbacks{};

bool callbacks_only = false;

}  // namespace

LogMessage::LogMessage(Level level,
                       std::string msg,
                       const char* function,
                       const char* file,
                       int line)
    : level(level),
      msg(std::move(msg)),
      time(std::chrono::system_clock::now()),
      function(function),
      file(file),
      line(line) {}

LogMessage::LogMessage(Level level,
                       const std::wstring& msg,
                       const char* function,
                       const char* file,
                       int line)
    : level(level),
      msg(utils::narrow(msg)),
      time(std::chrono::system_clock::now()),
      function(function),
      file(file),
      line(line) {}

#pragma region Formatting

namespace {

const std::string TRUNCATION_PREFIX = "~ ";

/**
 * @brief Truncates leading chunks of a string until it fits under a max width.
 * @note Will return strings longer than the max width if it can't cleanly chunk them.
 *
 * @param str The string to truncate.
 * @param separators The characters to use as separators between chunks.
 * @param max_width The maximum width of the string.
 * @return The truncated string.
 */
std::string truncate_leading_chunks(const std::string& str,
                                    const std::string& separators,
                                    size_t max_width) {
    auto width = str.size();
    size_t start_pos = 0;
    while (width > max_width) {
        auto next_separator_char = str.find_first_of(separators, start_pos);
        if (next_separator_char == std::string::npos) {
            break;
        }
        auto next_regular_char = str.find_first_not_of(separators, next_separator_char);
        if (next_regular_char == std::string::npos) {
            break;
        }

        // The first time we truncate something, we know we noew need to add the prefix on, so
        // subtract it from max width
        if (start_pos == 0) {
            max_width -= TRUNCATION_PREFIX.size();
        }

        width -= (next_regular_char - start_pos);
        start_pos = next_regular_char;
    }

    if (start_pos == 0) {
        return str;
    }

    return TRUNCATION_PREFIX + str.substr(start_pos);
}

/**
 * @brief Gets the name of a log level.
 *
 * @param level The log level
 * @return The level's name.
 */
std::string get_level_name(Level level) {
    switch (level) {
        default:
        case Level::ERROR:
            return "ERR";
        case Level::WARNING:
            return "WARN";
        case Level::INFO:
            return "INFO";
        case Level::DEV_WARNING:
            return "DWRN";
        case Level::MISC:
            return "MISC";
    }
}

constexpr auto DATE_WIDTH = 10;
constexpr auto TIME_WIDTH = 12;
constexpr auto LOCATION_WIDTH = 50;
constexpr auto LINE_WIDTH = 4;
constexpr auto LEVEL_WIDTH = 4;

/**
 * @brief Formats a log message following our internal style.
 *
 * @param msg The log message.
 * @return The formatted message
 */
std::string format_message(const LogMessage& msg) {
    auto location = (msg.function != nullptr && msg.function[0] != '\0')
                        ? truncate_leading_chunks(msg.function, ":", LOCATION_WIDTH)
                        : truncate_leading_chunks(msg.file, "\\/", LOCATION_WIDTH);

    return unrealsdk::fmt::format(
        "{1:>{0}%F %T}Z {3:>{2}}@{5:<{4}d} {7:>{6}}| {8}\n", DATE_WIDTH + 1 + TIME_WIDTH + 1,
        std::chrono::round<std::chrono::milliseconds>(msg.time), LOCATION_WIDTH, location,
        LINE_WIDTH, msg.line, LEVEL_WIDTH, get_level_name(msg.level), msg.msg);
}

/**
 * @brief Gets a header to display at the top of the log file
 *
 * @return The header.
 */
std::string get_header(void) {
    return unrealsdk::fmt::format("{1:<{0}} {3:<{2}} {5:>{4}}@{7:<{6}} {9:>{8}}| \n", DATE_WIDTH,
                                  "date", TIME_WIDTH + 1, "time", LOCATION_WIDTH, "location",
                                  LINE_WIDTH, "line", LEVEL_WIDTH, "v");
}

}  // namespace

#pragma endregion

namespace {

/**
 * @brief Gets a log level from it's string representation.
 *
 * @param str The string.
 * @return The parsed log level, or `Level::INVALID`.
 */
Level get_level_from_string(const std::string& str) {
    if (str.empty()) {
        return Level::INVALID;
    }

    // Start by matching first character
    switch (str[0]) {
        case 'E':
            return Level::ERROR;
        case 'W':
            return Level::WARNING;
        case 'I':
            return Level::INFO;
        case 'D':
            return Level::DEV_WARNING;
        case 'M':
            return Level::MISC;
        default:
            break;
    }

    // Otherwise try parse as an int
    uint32_t int_level = 0;
    auto res = std::from_chars(str.c_str(), str.c_str() + str.size(), int_level);
    if (res.ec == std::errc()) {
        return Level::INVALID;
    }
    // If within range
    if (static_cast<decltype(int_level)>(Level::MIN) <= int_level
        && int_level <= static_cast<decltype(int_level)>(Level::MAX)) {
        return static_cast<Level>(int_level);
    }

    return Level::INVALID;
}

}  // namespace

void init(const std::string& filename, bool callbacks_only_arg) {
    static bool initialized = false;
    if (initialized) {
        return;
    }
    initialized = true;

    callbacks_only = callbacks_only_arg;
    if (callbacks_only) {
        return;
    }

    auto env_level = get_level_from_string(env::get(env::LOG_LEVEL));
    if (env_level != Level::INVALID) {
        unreal_console_level = env_level;
    }

#ifdef NDEBUG
    if (env::defined(env::EXTERNAL_CONSOLE))
#endif
    {
        if (AllocConsole() != 0) {
            external_console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
            if (external_console_handle == nullptr) {
                LOG(ERROR, "Failed to get handle to external console!");
            }
        } else {
            LOG(ERROR, "Failed to initialize external console!");
        }
    }

    log_file_stream = std::make_unique<std::ofstream>(filename, std::ofstream::trunc);
    *log_file_stream << get_header() << std::flush;
}

void log(const LogMessage&& msg) {
    const std::lock_guard<std::mutex> lock(mutex);

    for (const auto& callback : all_log_callbacks) {
        callback(msg);
    }

    if (callbacks_only) {
        return;
    }

    if (unreal_console_level <= msg.level) {
        unrealsdk::uconsole_output_text(utils::widen(msg.msg));
    }

    if (external_console_handle != nullptr || log_file_stream) {
        auto formatted = format_message(msg);

        if (external_console_handle != nullptr) {
            WriteFile(external_console_handle, formatted.c_str(), (DWORD)formatted.size(), nullptr,
                      nullptr);
        }

        if (log_file_stream) {
            *log_file_stream << formatted << std::flush;
        }
    }
}

void set_console_level(Level level) {
    if (Level::MIN > level || level > Level::MAX) {
        throw std::out_of_range("Log level out of range!");
    }
    unreal_console_level = level;
}

void add_callback(log_callback callback) {
    const std::lock_guard<std::mutex> lock(mutex);

    all_log_callbacks.push_back(callback);
}

void remove_callback(log_callback callback) {
    const std::lock_guard<std::mutex> lock(mutex);

    all_log_callbacks.erase(
        std::remove(all_log_callbacks.begin(), all_log_callbacks.end(), callback),
        all_log_callbacks.end());
}

}  // namespace unrealsdk::logging