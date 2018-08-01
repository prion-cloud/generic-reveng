#include <functional>
#include <variant>

#include "data_flow.h"

data_value taint::data_flow_abstracted::operand::evaluate(std::vector<instruction::operand> const& operands) const
{
    auto dv = data_value(std::visit([operands](std::variant<unsigned, instruction::operand> const& variant)
    {
        if (variant.index() == 0)
            return operands.at(std::get<0>(variant));

        return std::get<1>(variant);
    }, value_));

    if (!modifier_.has_value())
        return dv;

    switch (*modifier_)
    {
    case modifier::neg:
        return dv.negate();
    case modifier::inv:
        return dv.invert();
    case modifier::ref:
        return dv.reference();
    case modifier::ind:
        return dv.indirect();
    }

    throw std::runtime_error("Invalid modifier");
}

taint::data_flow_contextual taint::data_flow_abstracted::make_contextual(std::vector<instruction::operand> const& context) const
{
    data_flow_contextual cont;

    cont.destination = destination_.evaluate(context);
    for (auto const& source : sources_)
        cont.sources.push_back(source.evaluate(context));

    if (operation_.has_value())
    {
        switch (*operation_)
        {
        case operation::add:
            cont.operation = [](auto const& sources) { return sources.front()->add(*sources.at(1)); };
            break;
        case operation::sub:
            cont.operation = [](auto const& sources) { return sources.front()->sub(*sources.at(1)); };
            break;
        case operation::mul:
            cont.operation = [](auto const& sources) { return sources.front()->mul(*sources.at(1)); };
            break;
        case operation::div:
            cont.operation = [](auto const& sources) { return sources.front()->div(*sources.at(1)); };
            break;
        }
    }
    else cont.operation = [](auto const& sources) { return *sources.front(); };

    return cont;
}
