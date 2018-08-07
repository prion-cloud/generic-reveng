#include "translator.h"

value translator::flow::specificator::evaluate(instruction const& instruction) const
{
    auto const& operand = std::visit([instruction](std::variant<unsigned, instruction::operand> const& variant)
    {
        if (variant.index() == 0)
            return instruction.operands.at(std::get<0>(variant));

        return std::get<1>(variant);
    }, value_);

    auto const result = value(operand);

    if (!modification_.has_value())
        return result;

    switch (*modification_)
    {
    case modification::neg:
        return result.negate();
    case modification::inv:
        return result.invert();
    case modification::ref:
        return result.reference();
    case modification::ind:
        return result.indirect();
    default:
        throw std::runtime_error("Unknown modification");
    }
}

std::pair<value, value> translator::flow::evaluate(instruction const& instruction) const
{
    auto const destination = destination_.evaluate(instruction);
    auto const source = sources_.front().evaluate(instruction);

    if (!operation_.has_value())
        return std::make_pair(destination, source);

    switch (*operation_)
    {
    case operation::add:
        return std::make_pair(destination, source + sources_.at(1).evaluate(instruction));
    case operation::sub:
        return std::make_pair(destination, source - sources_.at(1).evaluate(instruction));
    case operation::mul:
        return std::make_pair(destination, source * sources_.at(1).evaluate(instruction));
    case operation::div:
        return std::make_pair(destination, source / sources_.at(1).evaluate(instruction));
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
