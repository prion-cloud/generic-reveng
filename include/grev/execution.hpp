#pragma once

#include <forward_list>

#include <grev/execution_path.hpp>

namespace grev
{
    using execution = std::forward_list<execution_path>;
}
