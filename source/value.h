#pragma once
#include "instruction.h"

class value
{
public:

    explicit value(instruction::operand const& operand);

    value negate() const;
    value invert() const;
    value reference() const; // & ] [
    value indirect() const;  // * [ ]

    value operator+(value const& other) const;
    value operator-(value const& other) const;
    value operator*(value const& other) const;
    value operator/(value const& other) const;
};
