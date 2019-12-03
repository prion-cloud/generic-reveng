#pragma once

#include <generic-reveng/analysis/execution_state.hpp>

namespace grev
{
    struct execution_update
    {
        execution_state state;
        execution_fork fork;
    };
}
