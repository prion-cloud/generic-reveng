#include "stdafx.h"

#include "expr.h"

expr::op_unary::op_unary(const char op, node* const next)
    : op_(op), next_(next) { }
std::string expr::op_unary::evaluate() const
{
    return std::string("(") + op_ + next_->evaluate() + ")";
}
expr::op_binary::op_binary(const char op, node* const left, node* const right)
    : op_(op), left_(left), right_(right) { }
std::string expr::op_binary::evaluate() const
{
    return "(" + left_->evaluate() + " " + op_ + " " + right_->evaluate() + ")";
}

expr::constant::constant(const int64_t value)
    : value_(value) { }
std::string expr::constant::evaluate() const
{
    std::ostringstream ss;
    if (value_ < 0)
        ss << "(-" << std::hex << std::uppercase << -value_ << ")";
    else ss << std::hex << std::uppercase << value_;
    return ss.str();
}
expr::variable::variable(const x86_reg id)
    : id_(id) { }
std::string expr::variable::evaluate() const
{
    csh cs;
    cs_open(CS_ARCH_X86, CS_MODE_64, &cs);

    std::string string = cs_reg_name(cs, id_);

    cs_close(&cs);

    return string;
}

std::string expr::evaluate() const
{
    return root_->evaluate();
}

expr expr::wrap(const char op) const
{
    return expr(new op_unary(op, root_));
}
expr expr::append(const char op, const expr other) const
{
    return expr(new op_binary(op, root_, other.root_));
}

expr expr::make_const(const int64_t value)
{
    return expr(new constant(value));
}
expr expr::make_var(const x86_reg id)
{
    return expr(new variable(id));
}

bool operator<(const expr& expr1, const expr& expr2)
{
    return expr1.evaluate() < expr2.evaluate();
}

expr::expr(node* const root)
    : root_(root) { }
