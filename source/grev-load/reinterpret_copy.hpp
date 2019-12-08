#pragma once

#include <string_view>

namespace grev
{
    template <typename T, typename CharT, typename Traits>
    void reinterpret_copy(T* destination, std::basic_string_view<CharT, Traits> const& source);
}

#ifndef LINT
#include "reinterpret_copy.tpp"
#endif
