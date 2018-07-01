#include "stdafx.h"

#include "expr_tree.h"

expr_tree_x86::constant::constant(const int64_t value)
    : value(value) { }
std::string expr_tree_x86::constant::to_string() const
{
    std::ostringstream ss;
    if (value < 0)
        ss << "(-" << std::hex << std::uppercase << -value << ")";
    else ss << std::hex << std::uppercase << value;
    return ss.str();
}
bool expr_tree_x86::constant::is_const() const
{
    return true;
}
expr_tree_x86::node* expr_tree_x86::constant::neg() const
{
    return new constant(-value);
}

expr_tree_x86::variable::variable(const x86_reg id, const bool negative)
    : id(id), negative(negative) { }
std::string expr_tree_x86::variable::to_string() const
{
    std::ostringstream ss;
    if (negative)
        ss << "(-";
    csh cs;
    cs_open(CS_ARCH_X86, CS_MODE_64, &cs);
    ss << cs_reg_name(cs, id);
    cs_close(&cs);
    if (negative)
        ss << ")";
    return ss.str();
}
bool expr_tree_x86::variable::is_const() const
{
    return false;
}
expr_tree_x86::node* expr_tree_x86::variable::neg() const
{
    return new variable(id, !negative);
}

std::string expr_tree_x86::table::to_string() const
{
    std::ostringstream ss;

    const auto size0 = entries.size();

    for (unsigned i = 0; i < size0; ++i)
    {
        if (i > 0)
            ss << " + ";

        const auto size1 = entries.at(i).size();
        for (unsigned j = 0; j < size1; ++j)
        {
            if (j > 0)
                ss << " * ";
            
            ss << entries.at(i).at(j)->to_string();
        }
    }

    return ss.str();
}
bool expr_tree_x86::table::is_zero() const
{
    return entries.size() == 1 && entries.at(0).size() == 1 && entries.front().front()->is_const()
        && dynamic_cast<const constant*>(entries.front().front())->value == 0;
}
bool expr_tree_x86::table::is_one() const
{
    return entries.size() == 1 && entries.at(0).size() == 1 && entries.front().front()->is_const()
        && dynamic_cast<const constant*>(entries.front().front())->value == 1;
}

const expr_tree_x86* expr_tree_x86::neg() const
{
    std::vector<std::vector<const node*>> entries;
    for (const auto& orig_row : numerator_.entries)
    {
        std::vector<const node*> new_row;
        new_row.push_back(orig_row.front()->neg());
        new_row.insert(new_row.end(), orig_row.begin() + 1, orig_row.end());

        entries.push_back(new_row);
    }

    return new expr_tree_x86(table { entries }, denominator_);
}

const expr_tree_x86* expr_tree_x86::add(const expr_tree_x86* other) const
{
    if (denominator_.to_string() == other->denominator_.to_string())
        return new expr_tree_x86(numerator_ + other->numerator_, denominator_);

    return new expr_tree_x86(
        numerator_ * other->denominator_ + other->numerator_ * denominator_,
        denominator_ * other->denominator_);
}
const expr_tree_x86* expr_tree_x86::sub(const expr_tree_x86* other) const
{
    return add(other->neg());
}
const expr_tree_x86* expr_tree_x86::mul(const expr_tree_x86* other) const
{
    return new expr_tree_x86(numerator_ * other->numerator_, denominator_ * other->denominator_);
}
const expr_tree_x86* expr_tree_x86::div(const expr_tree_x86* other) const
{
    return new expr_tree_x86(numerator_ * other->denominator_, denominator_ * other->numerator_);
}
const expr_tree_x86* expr_tree_x86::mod(const expr_tree_x86* other) const
{
    return sub(div(other)->mul(other));
}

std::string expr_tree_x86::to_string() const
{
    std::ostringstream ss;

    const auto denom = !denominator_.is_one();
    if (denom && numerator_.entries.size() > 1)
        ss << "(";

    ss << numerator_.to_string();

    if (denom)
    {
        if (numerator_.entries.size() > 1)
            ss << ")";
        ss << " / " << denominator_.to_string();
    }

    return ss.str();
}

const expr_tree_x86* expr_tree_x86::make_const(const int64_t value)
{
    return new expr_tree_x86(table { {{ new constant(value) }} }, table { {{ new constant(1) }} });
}
const expr_tree_x86* expr_tree_x86::make_var(const x86_reg id)
{
    return new expr_tree_x86(table { {{ new variable(id, false) }} }, table { {{ new constant(1) }} });
}

bool operator<(const expr_tree_x86& expr1, const expr_tree_x86& expr2)
{
    return expr1.to_string() < expr2.to_string();
}

expr_tree_x86::table operator+(const expr_tree_x86::table& table1, const expr_tree_x86::table& table2)
{
    expr_tree_x86::table result;

    std::vector<const expr_tree_x86::constant*> constants;

    for (const auto& next : table1.entries)
    {
        if (next.size() == 1 && next.front()->is_const())
            constants.push_back(dynamic_cast<const expr_tree_x86::constant*>(next.front()));
        else result.entries.push_back(next);
    }
    for (const auto& next : table2.entries)
    {
        if (next.size() == 1 && next.front()->is_const())
            constants.push_back(dynamic_cast<const expr_tree_x86::constant*>(next.front()));
        else result.entries.push_back(next);
    }

    if (!constants.empty())
    {
        auto value = constants.front()->value;
        for (unsigned i = 1; i < constants.size(); ++i)
            value += constants.at(i)->value;

        if (value != 0 || result.entries.empty())
            result.entries.push_back({ new expr_tree_x86::constant(value) });
    }

    return result;
}
expr_tree_x86::table operator*(const expr_tree_x86::table& table1, const expr_tree_x86::table& table2)
{
    expr_tree_x86::table result;

    for (const auto& next1 : table1.entries)
    {
        for (const auto& next2 : table2.entries)
        {
            std::vector<const expr_tree_x86::constant*> constants;

            std::vector<const expr_tree_x86::node*> next;
            for (const auto n : next1)
            {
                if (n->is_const())
                    constants.push_back(dynamic_cast<const expr_tree_x86::constant*>(n));
                else next.push_back(n);
            }
            for (const auto n : next2)
            {
                if (n->is_const())
                    constants.push_back(dynamic_cast<const expr_tree_x86::constant*>(n));
                else next.push_back(n);
            }

            if (!constants.empty())
            {
                auto value = constants.front()->value;
                for (unsigned i = 1; i < constants.size(); ++i)
                    value *= constants.at(i)->value;

                if (value != 1 || next.empty())
                    next.push_back(new expr_tree_x86::constant(value));
            }

            result.entries.push_back(next);
        }
    }

    return result;
}

expr_tree_x86::expr_tree_x86(table numerator, table denominator)
    : numerator_(std::move(numerator)), denominator_(std::move(denominator))
{
    if (numerator_.is_zero())
        denominator_ = table { {{ new constant(1) }} };
}
