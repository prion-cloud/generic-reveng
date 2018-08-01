#pragma once

#include <unordered_map>

#include "ir.h"

namespace taint
{
    class data_monitor
    {
        class data_map
        {
            std::unordered_map<data_value, data_value> base_;

        public:

            data_value* operator[](data_value const& key);
            std::vector<data_value*> operator[](std::vector<data_value> const& keys);
        };

        ir const& ir_;

        data_map data_map_;

    public:

        explicit data_monitor(ir const& ir);

        void commit(instruction const& instruction);
    };
}
