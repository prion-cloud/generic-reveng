#include "intermediate.h"

std::vector<data_flow> const& data_ir::operator[](unsigned const instruction) const
{
    auto const it = base_.find(instruction);

    if (it == base_.end())
        throw std::runtime_error("Unknown instruction");

    return it->second;
}
