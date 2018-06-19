#include "stdafx.h"

#include "taint.h"

/*
var_loc::var_loc() = default;
var_loc::var_loc(const loc_type type, const uint64_t value)
    : type(type), value(value) { }
*/

code_constraint::code_constraint(const code_constraint_type type, const uint64_t id, const int64_t value)
    : type(type), id(id), value(value) { }

bool operator<(const code_constraint& constr1, const code_constraint& constr2)
{
    if (constr1.type == constr2.type)
        return constr1.value < constr2.value;

    return constr1.type < constr2.type;
}

code_constraint code_constraint::none()
{
    return code_constraint(code_constraint_type::none, 0, 0);
}

var_expr::operand_un::operand_un(const std::shared_ptr<node> next, const std::function<int64_t(int64_t)> function)
    : next_(next), function_(function) { }
int64_t var_expr::operand_un::evaluate() const
{
    return function_(next_->evaluate());
}

var_expr::operand_bin::operand_bin(const std::shared_ptr<node> left, const std::shared_ptr<node> right, const std::function<int64_t(int64_t, int64_t)> function)
    : left_(left), right_(right), function_(function) { }
int64_t var_expr::operand_bin::evaluate() const
{
    return function_(left_->evaluate(), right_->evaluate());
}

var_expr::constant::constant(const operand_x86 source)
    : source_(source) { }
int64_t var_expr::constant::evaluate() const
{
    return 0; // TODO
}

var_expr::var_expr() = default;
var_expr::var_expr(const operand_x86 root_source)
{
    root_ = std::make_shared<constant>(root_source);
}

int64_t var_expr::evaluate() const
{
    return root_->evaluate();
}

void var_expr::neg()
{
    root_ = std::make_shared<operand_un>(root_, [](const int64_t value)
    {
        return -value;
    });
}

void var_expr::add(const var_expr expression)
{
    root_ = std::make_shared<operand_bin>(root_, expression.root_, [](const int64_t left, const int64_t right)
    {
        return left + right;
    });
}
void var_expr::sub(const var_expr expression)
{
    root_ = std::make_shared<operand_bin>(root_, expression.root_, [](const int64_t left, const int64_t right)
    {
        return left - right;
    });
}

void var_expr::mul(const var_expr expression)
{
    root_ = std::make_shared<operand_bin>(root_, expression.root_, [](const int64_t left, const int64_t right)
    {
        return left * right;
    });
}
void var_expr::div(const var_expr expression)
{
    root_ = std::make_unique<operand_bin>(root_, expression.root_, [](const int64_t left, const int64_t right)
    {
        return left / right;
    });
}
