#pragma once

#include <forward_list>
#include <list>

#include <grev/execution_path.hpp>

namespace grev
{
    struct execution
    {
        std::forward_list<execution_path> paths;

        /*!
         *  The execution states during import calls, trimmed to the respective import's dependencies.
         */
        std::list<std::pair<std::uint32_t, execution_state>> import_calls;
    };
}
