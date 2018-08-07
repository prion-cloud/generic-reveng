#pragma once

#include <unordered_map>

#include "instruction.h"
#include "translator.h"
#include "value.h"

class monitor
{
    class data_map
    {
        std::unordered_map<value, value> base_;

    public:

        value& operator[](value const& key);
        value const& operator[](value const& key) const;
    };

    translator const& translator_;

    data_map data_map_;

public:

    explicit monitor(translator const& translator);

    void commit(instruction const& instruction);
};
