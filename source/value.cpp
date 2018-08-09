#include "value.h"

value::value() = default;

value::value(operand const& operand)
{
    throw std::runtime_error("TODO");
}

value value::reference() const
{
    throw std::runtime_error("TODO");
}
value value::indirect() const
{
    throw std::runtime_error("TODO");
}

value value::operator-() const
{
    throw std::runtime_error("TODO");
}
value value::operator~() const
{
    throw std::runtime_error("TODO");
}

value value::operator+(value const& other) const
{
    throw std::runtime_error("TODO");
}
value value::operator-(value const& other) const
{
    throw std::runtime_error("TODO");
}
value value::operator*(value const& other) const
{
    throw std::runtime_error("TODO");
}
value value::operator/(value const& other) const
{
    throw std::runtime_error("TODO");
}

bool operator==(value const& value1, value const& value2)
{
    value_hash const hash;
    return hash(value1) == hash(value2);
}

size_t value_hash::operator()(value const& value) const
{
    throw std::runtime_error("TODO");
}
