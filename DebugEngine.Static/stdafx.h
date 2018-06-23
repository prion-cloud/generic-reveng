#pragma once

#include <array>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include <Windows.h>

// Templated function
#define TPL template <typename T>

// Indicator for a successful method execution
#define RES_SUCCESS 0
// Indicator for a failed method execution
#define RES_FAILURE 1

// Throw a runtime exception containing the file name and the code line.
#define THROW(message) if (!global_flags.fat) { throw std::runtime_error("ERROR: " + std::string(message) + "\n[" + std::string(__FILE__) + ":" + std::to_string(__LINE__) + "]"); }

// Non-fatal error; return if expression evaluates to 'true'.
#define ERROR_IF(expr) { const int __RES__ = expr; if (__RES__) return __RES__; }
// Fatal error; throw exception if expression evaluates to 'true'.
#define FATAL_IF(expr) { const int __RES__ = expr; if (__RES__) THROW(std::string("`") + #expr + std::string("` (") + std::to_string(__RES__) + std::string(")")); }

#define STR_UNKNOWN "???"

struct flag_status
{
    // Disable fatal errors.
    bool fat;
    // Count most used ("hot") instructions.
    bool hot;
    // Do any memory allocation once it is needed.
    bool lazy;
    // Ignore failed instructions.
    bool ugly;
};

extern flag_status global_flags;
