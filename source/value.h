#pragma once

#include "instruction.h"

class value
{
    struct expr
    {
        
    };

public:

    value();

    explicit value(operand const& operand);

    value reference() const; // & ] [
    value indirect() const;  // * [ ]

    value operator-() const;
    value operator~() const;

    value operator+(value const& other) const;
    value operator-(value const& other) const;
    value operator*(value const& other) const;
    value operator/(value const& other) const;

    friend bool operator==(value const& value1, value const& value2);
};

class value_hash
{
    size_t operator()(value const& value) const;
};
