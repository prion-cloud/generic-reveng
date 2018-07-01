#include "stdafx.h"

#include "expr_tree.h"

expr_tree_x86::op<'+'>::op(std::vector<const node*> n)
{
    std::vector<const constant*> constants;
    for (const auto nn : n)
    {
        if (nn->is_const())
            constants.push_back(dynamic_cast<const constant*>(nn));
        else next.push_back(nn);
    }
    if (constants.empty())
        return;
    auto c = constants.front();
    for (unsigned i = 1; i < constants.size(); ++i)
        c = new constant(c->value + constants.at(i)->value);
    next.push_back(c);
}
template <char C>
std::string expr_tree_x86::op<C>::to_string() const
{
    std::ostringstream ss;
    ss << "(";
    for (unsigned i = 0; i < next.size(); ++i)
    {
        if (i > 0)
            ss << " " << C << " ";
        ss << next.at(i)->to_string();
    }
    ss << ")";
    return ss.str();
}
template <char C>
bool expr_tree_x86::op<C>::is_const() const
{
    return false;
}
template <char C>
expr_tree_x86::node* expr_tree_x86::op<C>::neg() const
{
    std::vector<const node*> n;
    for (const auto nn : next)
        n.push_back(nn->neg());
    return new op<C>(n);
}

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

const expr_tree_x86* expr_tree_x86::neg() const
{
    return new expr_tree_x86(root_->neg(), adds_);
}

const expr_tree_x86* expr_tree_x86::add(const expr_tree_x86* other) const
{
    std::vector<const node*> next;

    if (adds_.find(root_) == adds_.end())
        next.push_back(root_);
    else
    {
        const auto add_root = dynamic_cast<const op<'+'>*>(root_);
        next.insert(next.end(), add_root->next.begin(), add_root->next.end());
    }

    if (other->adds_.find(other->root_) == other->adds_.end())
        next.push_back(other->root_);
    else
    {
        const auto add_root = dynamic_cast<const op<'+'>*>(other->root_);
        next.insert(next.end(), add_root->next.begin(), add_root->next.end());
    }

    const auto adder = new op<'+'>(next);
    return new expr_tree_x86(adder, { adder });
}
const expr_tree_x86* expr_tree_x86::sub(const expr_tree_x86* other) const
{
    return add(other->neg());
}

std::string expr_tree_x86::to_string() const
{
    return root_->to_string();
}

const expr_tree_x86* expr_tree_x86::make_const(const int64_t value)
{
    return new expr_tree_x86(new constant(value), { });
}
const expr_tree_x86* expr_tree_x86::make_var(const x86_reg id)
{
    return new expr_tree_x86(new variable(id, false), { });
}

bool operator<(const expr_tree_x86& expr1, const expr_tree_x86& expr2)
{
    return expr1.to_string() < expr2.to_string();
}

expr_tree_x86::expr_tree_x86(const node* root, std::set<const void*> adds)
    : root_(root), adds_(std::move(adds)) { }
