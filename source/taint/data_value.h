#pragma once

#include "../instruction.h"

class data_value
{
public:

    data_value();

    explicit data_value(instruction::operand operand);

    data_value negate() const;
    data_value invert() const;
    data_value reference() const;
    data_value indirect() const;

    data_value add(data_value other) const;
    data_value sub(data_value other) const;
    data_value mul(data_value other) const;
    data_value div(data_value other) const;
};
