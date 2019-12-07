#pragma once

#include <forward_list>

#include <generic-reveng/analysis/execution_path.hpp>

namespace grev
{
    using execution = std::forward_list<execution_path>;
}
