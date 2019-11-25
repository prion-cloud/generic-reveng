#pragma once

#include <generic-reveng/analysis/z3/expression.hpp>

namespace grev
{
    using execution_fork = std::unordered_set<z3::expression>;
}
