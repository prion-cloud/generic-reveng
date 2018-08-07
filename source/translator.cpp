#include "translator.h"

value translator::flow::specificator::evaluate(instruction const& instruction) const
{
    auto const val = value(std::visit([instruction](std::variant<unsigned, instruction::operand> const& variant)
    {
        if (variant.index() == 0)
            return instruction.operands.at(std::get<0>(variant));

        return std::get<1>(variant);
    }, value_));

    if (!modification_.has_value())
        return val;

    switch (*modification_)
    {
    case modification::neg:
        return -val;
    case modification::inv:
        return ~val;
    case modification::ref:
        return val.reference();
    case modification::ind:
        return val.indirect();
    default:
        throw std::runtime_error("Unknown modification");
    }
}

std::pair<value, value> translator::flow::evaluate(instruction const& instruction) const
{
    return std::make_pair(destination_.evaluate(instruction), evaluate_sources(instruction));
}

value translator::flow::evaluate_sources(instruction const& instruction) const
{
    std::vector<value> values;
    for (auto const& source : sources_)
        values.push_back(source.evaluate(instruction));

    if (!operation_.has_value())
        return values.front();

    switch (*operation_)
    {
    case operation::add:
        return values.front() + values.at(1);
    case operation::sub:
        return values.front() - values.at(1);
    case operation::mul:
        return values.front() * values.at(1);
    case operation::div:
        return values.front() / values.at(1);
    default:
        throw std::runtime_error("Unknown operation");
    }
}

std::vector<std::pair<value, value>> translator::operator[](instruction const& instruction) const
{
    auto const& dict_it = dictionary_.find(instruction.id);

    if (dict_it == dictionary_.end())
        throw std::runtime_error("Unknown instruction");

    std::vector<std::pair<value, value>> translation;
    for (auto const& flow : dict_it->second)
        translation.push_back(flow.evaluate(instruction));

    return translation;
}
