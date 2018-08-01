#pragma once

#include <unordered_map>

#include "data_flow.h"

namespace taint
{
    class ir
    {
        std::unordered_map<unsigned, std::vector<data_flow_abstracted>> dictionary_;

    public:

        ir() = default;

        std::vector<data_flow_abstracted> const& operator[](unsigned instruction) const;
    };
}
