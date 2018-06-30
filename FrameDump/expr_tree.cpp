#include "stdafx.h"

#include "expr_tree.h"

expr_tree_x86::expr_tree_x86(const int64_t value)
    : type_(t_const), value_(value), left_(nullptr), right_(nullptr) { }
expr_tree_x86::expr_tree_x86(const x86_reg id)
    : type_(t_reg), value_(id), left_(nullptr), right_(nullptr) { }

expr_tree_x86* expr_tree_x86::add(const expr_tree_x86* other) const
{
    if (is_const() && other->is_const())
        return new expr_tree_x86(std::get<t_const>(value_) + std::get<t_const>(other->value_));

    if (is_var() || other->is_var())
        return new expr_tree_x86(op_bin::add, this, other);

    if (is_const())
    {
        if (other->left_->is_const())
            return new expr_tree_x86(op_bin::add, add(other->left_), other->right_);
        if (other->right_->is_const())
            return new expr_tree_x86(op_bin::add, other->left_, add(other->right_));
    }

    if (other->is_const())
    {
        if (left_->is_const())
            return new expr_tree_x86(op_bin::add, left_->add(other), right_);
        if (right_->is_const())
            return new expr_tree_x86(op_bin::add, left_, right_->add(other));
    }

    throw;
}

std::string expr_tree_x86::to_string() const
{
    std::ostringstream ss;
    switch (type_)
    {
    case t_const:
        {
            const auto value = std::get<t_const>(value_);
            if (value < 0)
                ss << "(-" << std::hex << std::uppercase << -value << ")";
            else ss << std::hex << std::uppercase << value;
        }
        break;
    case t_reg:
        {
            csh cs;
            cs_open(CS_ARCH_X86, CS_MODE_64, &cs);
            ss << cs_reg_name(cs, std::get<t_reg>(value_));
            cs_close(&cs);
        }
        break;
    case t_un:
        ss << "(" << map_un_.at(std::get<t_un>(value_)) << left_->to_string() << ")";
        break;
    case t_bin:
        ss << "(" << left_->to_string() << " " << map_bin_.at(std::get<t_bin>(value_)) << " " << right_->to_string() << ")";
        break;
    }
    return ss.str();
}

bool operator<(const expr_tree_x86& expr1, const expr_tree_x86& expr2)
{
    return expr1.to_string() < expr2.to_string();
}

expr_tree_x86::expr_tree_x86(const op_un op, const expr_tree_x86* next)
    : type_(t_un), value_(op), left_(next), right_(nullptr) { }
expr_tree_x86::expr_tree_x86(const op_bin op, const expr_tree_x86* left, const expr_tree_x86* right)
    : type_(t_bin), value_(op), left_(left), right_(right) { }

bool expr_tree_x86::is_const() const
{
    switch (type_)
    {
    case t_const:
        return true;
    case t_reg:
        return false;
    case t_un:
        return left_->is_const();
    case t_bin:
        return left_->is_const() && right_->is_const();
    }

    throw;
}
bool expr_tree_x86::is_var() const
{
    switch (type_)
    {
    case t_const:
        return false;
    case t_reg:
        return true;
    case t_un:
        return left_->is_var();
    case t_bin:
        return left_->is_var() && right_->is_var();
    }

    throw;
}
