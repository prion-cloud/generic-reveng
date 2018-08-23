#pragma once

#include <unordered_map>

#include "instruction.h"
#include "translator.h"
#include "value.h"

class monitor
{
    class value_map
    {
        std::unordered_map<value, value, value_hash> base_;

    public:

        value& operator[](value const& key);
        value const& operator[](value const& key) const;
    };

    translator const& translator_;

    value_map value_map_;

public:

    explicit monitor(translator const& translator);

    void commit(instruction const& instruction);
};
