#pragma once

// ReSharper disable CppUnusedIncludeDirective

#include <array>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <Windows.h>

// Templated function
#define TPL template <typename T>

// Indicator for a successful method execution
#define R_SUCCESS 0
// Indicator for a failed method execution
#define R_FAILURE 1

// Throw a runtime exception containing the file name and the code line.
#define THROW if (global_flag_status.fat) { throw std::runtime_error("ERROR [" + std::string(__FILE__) + ":" + std::to_string(__LINE__) + "]"); }

// Non-fatal error; return as failure if condition is true.
#define E_ERR(expr) if (expr) { return R_FAILURE; }
// Fatal error; throw exception if condition is true.
#define E_FAT(expr) if (expr) { THROW; }

#define STR_UNKNOWN "???"

struct flag_status
{
    // Enable fatal errors.
    bool fat = true;
    // Do any memory allocation once it is needed.
    bool lazy = false;
    // Ignore failed instructions.
    bool ugly = false;
};

extern flag_status global_flag_status;
