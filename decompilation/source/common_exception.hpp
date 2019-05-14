#pragma once

#include <stdexcept>

inline std::runtime_error unknown_architecture() noexcept
{
    return std::runtime_error("Unknown architecture");
}
inline std::runtime_error invalid_binary_format() noexcept
{
    return std::runtime_error("Invalid binary format");
}
