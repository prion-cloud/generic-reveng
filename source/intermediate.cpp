#include "intermediate.h"

data_operator::data_operator() = default;

data_operand::data_operand() = default;

data_flow::data_flow() = default;

data_ir::data_ir() = default;

std::vector<data_flow> const& data_ir::operator[](unsigned const instruction) const
{
    auto const it = base_.find(instruction);

    if (it == base_.end())
        throw std::runtime_error("Unknown instruction");

    return it->second;
}
