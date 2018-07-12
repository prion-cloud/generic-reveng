#include "stdafx.h"

#include "data_flow.h"

bool data_flow::expression::node::is_const(int64_t) const
{
    return false;
}
std::optional<x86_reg> data_flow::expression::node::get_reg_value() const
{
    return std::nullopt;
}
std::optional<int64_t> data_flow::expression::node::get_const_value() const
{
    return std::nullopt;
}
std::optional<int64_t> data_flow::expression::node::get_add_value() const
{
    return std::nullopt;
}

data_flow::expression::constant::constant(const int64_t value)
    : value(value) { }
std::string data_flow::expression::constant::to_string() const
{
    std::ostringstream ss;
    ss << std::hex << std::uppercase;
    if (value < 0)
        ss << "(-" << -value << ")";
    else ss << value;

    return ss.str();
}
bool data_flow::expression::constant::is_const(const int64_t value) const
{
    return this->value == value;
}
std::optional<int64_t> data_flow::expression::constant::get_const_value() const
{
    return value;
}

template<char C>
data_flow::expression::op_assoc<C>::op_assoc(std::vector<node*> next, const int64_t base,
    const std::function<int64_t(int64_t, int64_t)>& func)
{
    std::vector<node*> pre_next;
    for (const auto n : next)
    {
        const auto op = dynamic_cast<op_assoc<C>*>(n);
        if (op == nullptr)
            pre_next.push_back(n);
        else pre_next.insert(pre_next.end(), op->next.begin(), op->next.end());
    }

    std::vector<constant*> const_next;
    for (const auto n : pre_next)
    {
        const auto c = dynamic_cast<constant*>(n);
        if (c == nullptr)
            this->next.push_back(n);
        else const_next.push_back(c);
    }

    auto value = base;
    for (const auto n : const_next)
        value = func(value, n->value);

    if (value != base)
        this->next.push_back(new constant(value));
}
template<char C>
std::string data_flow::expression::op_assoc<C>::to_string() const
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

data_flow::expression::op_add::op_add(const std::vector<node*>& next)
    : op_assoc<'+'>(next, 0, [](const int64_t a, const int64_t b) { return a + b; }) { }
std::optional<int64_t> data_flow::expression::op_add::get_add_value() const
{
    return next.at(1)->get_const_value();
}
data_flow::expression::op_mul::op_mul(const std::vector<node*>& next)
    : op_assoc<'*'>(next, 1, [](const int64_t a, const int64_t b) { return a * b; }) { }

template<char C>
data_flow::expression::op_unary<C>::op_unary(node* next)
    : next(next) { }
template<char C>
std::string data_flow::expression::op_unary<C>::to_string() const
{
    std::ostringstream ss;
    ss << "(" << C << "(" << next->to_string() << "))";
    return ss.str();
}

template<char C>
data_flow::expression::op<C>::op(node* const left, node* const right)
    : left(left), right(right) { }
template<char C>
std::string data_flow::expression::op<C>::to_string() const
{
    std::ostringstream ss;
    ss << "(" << left->to_string() << " " << C << " " << right->to_string() << ")";

    return ss.str();
}

data_flow::expression::var_register::var_register(const x86_reg id)
    : id(id)
{
    if (id == X86_REG_INVALID)
        throw;
}
std::string data_flow::expression::var_register::to_string() const
{
    std::ostringstream ss;

    csh cs;
    cs_open(CS_ARCH_X86, CS_MODE_64, &cs);

    ss << cs_reg_name(cs, id);

    cs_close(&cs);

    return ss.str();
}
std::optional<x86_reg> data_flow::expression::var_register::get_reg_value() const
{
    return id;
}
data_flow::expression::var_memory::var_memory(node* const descriptor)
    : descriptor(descriptor) { }
std::string data_flow::expression::var_memory::to_string() const
{
    std::ostringstream ss;
    ss << "[" << descriptor->to_string() << "]";

    return ss.str();
}

std::string data_flow::expression::to_string() const
{
    return root_->to_string();
}

std::optional<x86_reg> data_flow::expression::get_reg_value() const
{
    return root_->get_reg_value();
}
std::optional<int64_t> data_flow::expression::get_const_value() const
{
    return root_->get_const_value();
}
std::optional<int64_t> data_flow::expression::get_add_value() const
{
    return root_->get_add_value();
}

data_flow::expression data_flow::expression::memorize() const
{
    return expression(new var_memory(root_));
}

data_flow::expression data_flow::expression::make_var(const x86_reg id)
{
    return expression(new var_register(id));
}
data_flow::expression data_flow::expression::make_const(const int64_t value)
{
    return expression(new constant(value));
}

data_flow::expression data_flow::expression::operator-() const
{
    const auto c = dynamic_cast<constant*>(root_);
    if (c == nullptr)
        return expression(new op_unary<'-'>(root_));

    return make_const(-c->value);
}
data_flow::expression data_flow::expression::operator~() const
{
    const auto c = dynamic_cast<constant*>(root_);
    if (c == nullptr)
        return expression(new op_unary<'~'>(root_));

    return make_const(~c->value);
}

data_flow::expression operator+(const data_flow::expression& expr1, const data_flow::expression& expr2)
{
    if (expr1.root_->is_const(0))
        return expr2;
    if (expr2.root_->is_const(0))
        return expr1;

    data_flow::expression::node* root;
    const auto add = new data_flow::expression::op_add({ expr1.root_, expr2.root_ });
    if (add->next.size() < 2)
    {
        if (add->next.empty())
            return data_flow::expression::make_const(0);

        root = add->next.front();
    }
    else root = add;

    return data_flow::expression(root);
}
data_flow::expression operator-(const data_flow::expression& expr1, const data_flow::expression& expr2)
{
    return expr1 + -expr2;
}
data_flow::expression operator*(const data_flow::expression& expr1, const data_flow::expression& expr2)
{
    if (expr1.root_->is_const(0) || expr2.root_->is_const(0))
        return data_flow::expression::make_const(0);

    if (expr1.root_->is_const(1))
        return expr2;
    if (expr2.root_->is_const(1))
        return expr1;

    data_flow::expression::node* root;
    const auto mul = new data_flow::expression::op_mul({ expr1.root_, expr2.root_ });
    if (mul->next.size() < 2)
        root = mul->next.front();
    else root = mul;

    return data_flow::expression(root);
}
data_flow::expression operator/(const data_flow::expression& expr1, const data_flow::expression& expr2)
{
    return data_flow::expression(new data_flow::expression::op<'/'>(expr1.root_, expr2.root_));
}
data_flow::expression operator%(const data_flow::expression& expr1, const data_flow::expression& expr2)
{
    return data_flow::expression(new data_flow::expression::op<'%'>(expr1.root_, expr2.root_));
}

data_flow::expression operator&(const data_flow::expression& expr1, const data_flow::expression& expr2)
{
    return data_flow::expression(new data_flow::expression::op<'&'>(expr1.root_, expr2.root_));
}
data_flow::expression operator|(const data_flow::expression& expr1, const data_flow::expression& expr2)
{
    return data_flow::expression(new data_flow::expression::op<'|'>(expr1.root_, expr2.root_));
}
data_flow::expression operator^(const data_flow::expression& expr1, const data_flow::expression& expr2)
{
    if (expr1.to_string() == expr2.to_string())
        return data_flow::expression::make_const(0);

    return data_flow::expression(new data_flow::expression::op<'^'>(expr1.root_, expr2.root_));
}

data_flow::expression operator<<(const data_flow::expression& expr1, const data_flow::expression& expr2)
{
    return data_flow::expression(new data_flow::expression::op<'<'>(expr1.root_, expr2.root_));
}
data_flow::expression operator>>(const data_flow::expression& expr1, const data_flow::expression& expr2)
{
    return data_flow::expression(new data_flow::expression::op<'>'>(expr1.root_, expr2.root_));
}

data_flow::expression::expression(node* root)
    : root_(root)
{
    if (root_ == nullptr)
        throw;
}

data_flow::expression_variant::expression_variant(const expression expr)
    : base_({ expr }) { }
data_flow::expression_variant::expression_variant(const int64_t value)
    : base_({ expression::make_const(value) }) { }

std::string data_flow::expression_variant::to_string() const
{
    std::ostringstream ss;
    for (unsigned i = 0; i < base_.size(); ++i)
    {
        if (i > 0)
            ss << " : ";
        ss << base_.at(i).to_string();
    }

    return ss.str();
}

void data_flow::expression_variant::concat(const expression_variant& other)
{
    base_.insert(base_.end(), other.base_.begin(), other.base_.end());
}

data_flow::expression data_flow::expression_variant::memorize() const
{
    if (base_.size() != 1)
        throw;

    return base_.front().memorize();
}

void data_flow::expression_variant::negate()
{
    for (auto& e : base_)
        e = -e;
}
void data_flow::expression_variant::invert()
{
    for (auto& e : base_)
        e = ~e;
}

data_flow::expression_variant& data_flow::expression_variant::operator+=(const expression_variant& expr_var)
{
    transform(expr_var, [](const expression e1, const expression e2) { return e1 + e2; });
    return *this;
}
data_flow::expression_variant& data_flow::expression_variant::operator-=(const expression_variant& expr_var)
{
    transform(expr_var, [](const expression e1, const expression e2) { return e1 - e2; });
    return *this;
}
data_flow::expression_variant& data_flow::expression_variant::operator*=(const expression_variant& expr_var)
{
    transform(expr_var, [](const expression e1, const expression e2) { return e1 * e2; });
    return *this;
}
data_flow::expression_variant& data_flow::expression_variant::operator/=(const expression_variant& expr_var)
{
    transform(expr_var, [](const expression e1, const expression e2) { return e1 / e2; });
    return *this;
}
data_flow::expression_variant& data_flow::expression_variant::operator%=(const expression_variant& expr_var)
{
    transform(expr_var, [](const expression e1, const expression e2) { return e1 % e2; });
    return *this;
}

data_flow::expression_variant& data_flow::expression_variant::operator&=(const expression_variant& expr_var)
{
    transform(expr_var, [](const expression e1, const expression e2) { return e1 & e2; });
    return *this;
}
data_flow::expression_variant& data_flow::expression_variant::operator|=(const expression_variant& expr_var)
{
    transform(expr_var, [](const expression e1, const expression e2) { return e1 | e2; });
    return *this;
}
data_flow::expression_variant& data_flow::expression_variant::operator^=(const expression_variant& expr_var)
{
    transform(expr_var, [](const expression e1, const expression e2) { return e1 ^ e2; });
    return *this;
}

data_flow::expression_variant& data_flow::expression_variant::operator<<=(const expression_variant& expr_var)
{
    transform(expr_var, [](const expression e1, const expression e2) { return e1 << e2; });
    return *this;
}
data_flow::expression_variant& data_flow::expression_variant::operator>>=(const expression_variant& expr_var)
{
    transform(expr_var, [](const expression e1, const expression e2) { return e1 >> e2; });
    return *this;
}

const std::vector<data_flow::expression>& data_flow::expression_variant::operator*() const
{
    return base_;
}

void data_flow::expression_variant::transform(expression_variant other, const std::function<expression(expression, expression)>& function)
{
    std::vector<expression> new_base;
    for (const auto e1 : base_)
    {
        for (const auto e2 : other.base_)
            new_base.push_back(function(e1, e2));
    }

    base_ = new_base;
}

std::vector<std::string> data_flow::expression_map::to_string() const
{
    std::vector<std::string> result;
    for (const auto& [expr, expr_var] : base_)
    {
        const auto s1 = expr.to_string();
        const auto s2 = expr_var.to_string();

        if (s1 != s2)
        {
            auto res = s1;
            res.append(" <- ");
            res.append(s2);
            result.push_back(res);
        }
    }

    return result;
}

data_flow::expression_variant data_flow::expression_map::effect(x86_op_mem mem)
{
    expression_variant expr_var = mem.disp;

    if (mem.base != X86_REG_INVALID)
        expr_var += operator[](static_cast<x86_reg>(mem.base));

    if (mem.index != X86_REG_INVALID)
    {
        auto sub = operator[](static_cast<x86_reg>(mem.index));
        sub *= mem.scale;
        expr_var += sub;
    }

    return expr_var;
}

data_flow::expression_variant& data_flow::expression_map::operator[](const expression& expr)
{
    if (base_.find(expr) == base_.end())
        base_.emplace(expr, expr);

    return base_[expr];
}
data_flow::expression_variant& data_flow::expression_map::operator[](x86_reg id)
{
    const auto it = reg_map_.find(id);
    if (it != reg_map_.end())
        id = it->second.first; // TODO: Scale

    return operator[](expression::make_var(id));
}
data_flow::expression_variant& data_flow::expression_map::operator[](const instruction::operand operand)
{
    switch (operand.type)
    {
    case instruction::op_register:
        return operator[](std::get<x86_reg>(operand.value));
    case instruction::op_immediate:
        return operator[](expression::make_const(std::get<int64_t>(operand.value)));
    case instruction::op_memory:
        return operator[](effect(std::get<x86_op_mem>(operand.value)).memorize());
    case instruction::op_float:
        return operator[](expression::make_const(static_cast<int64_t>(std::get<double>(operand.value))));
    default: throw;
    }
}

std::map<data_flow::expression, data_flow::expression_variant> const* data_flow::expression_map::operator->() const
{
    return &base_;
}
const std::map<data_flow::expression, data_flow::expression_variant>& data_flow::expression_map::operator*() const
{
    return base_;
}

data_flow::data_flow(const instruction& instruction)
{
    apply(instruction);
}
data_flow::data_flow(const instruction_sequence& instruction_sequence)
{
    sequence_ = instruction_sequence;

    for (unsigned i = 0; i < instruction_sequence->size(); ++i)
        apply(instruction_sequence->at(i));
}

std::vector<std::string> data_flow::to_string() const
{
    return map_.to_string();
}

void data_flow::apply(const instruction& instruction)
{
    if (instruction.operands.size() > 2)
        throw;

    std::optional<instruction::operand> op0 = std::nullopt;
    if (!instruction.operands.empty())
        op0.emplace(instruction.operands.at(0));
    std::optional<instruction::operand> op1 = std::nullopt;
    if (instruction.operands.size() > 1)
        op1.emplace(instruction.operands.at(1));
    
    map_[X86_REG_RIP] = static_cast<int64_t>(instruction.address + instruction.code.size());

    switch (instruction.id)
    {
    case X86_INS_ADD:
        map_[*op0] += map_[*op1];
        break;
    case X86_INS_AND:
        map_[*op0] &= map_[*op1];
        break;
    case X86_INS_CALL:
        map_[X86_REG_RSP] -= 8i64;
        map_[map_[X86_REG_RSP].memorize()] = map_[X86_REG_RIP];
        map_[X86_REG_RIP] = map_[*op0];
        break;
    case X86_INS_CMOVA:
    case X86_INS_CMOVAE:
    case X86_INS_CMOVB:
    case X86_INS_CMOVBE:
    case X86_INS_CMOVE:
    case X86_INS_CMOVG:
    case X86_INS_CMOVGE:
    case X86_INS_CMOVL:
    case X86_INS_CMOVLE:
    case X86_INS_CMOVNE:
    case X86_INS_CMOVNO:
    case X86_INS_CMOVNP:
    case X86_INS_CMOVNS:
    case X86_INS_CMOVO:
    case X86_INS_CMOVP:
    case X86_INS_CMOVS:
        map_[*op0].concat(map_[*op1]);
        break;
    case X86_INS_CMP:
        // TODO
        break;
    case X86_INS_DIV:
        {
            const auto dividend = map_[X86_REG_RAX];
            map_[X86_REG_RAX] = dividend / map_[*op0];
            map_[X86_REG_RDX] = dividend % map_[*op0];
        }
        break;
    case X86_INS_IMUL:
        if (!op1.has_value())
            map_[X86_REG_RAX] *= map_[*op0];
        else map_[*op0] *= map_[*op1];
        break;
    case X86_INS_LEA:
        map_[*op0] = map_.effect(std::get<x86_op_mem>(op1->value));
        break;
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JB:
    case X86_INS_JBE:
    case X86_INS_JCXZ:
    case X86_INS_JE:
    case X86_INS_JG:
    case X86_INS_JGE:
    case X86_INS_JL:
    case X86_INS_JLE:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JS:
        map_[X86_REG_RIP].concat(map_[*op0]);
        break;
    case X86_INS_JMP:
        map_[X86_REG_RIP] = map_[*op0];
        break;
    case X86_INS_MOV:
    case X86_INS_MOVABS:
    case X86_INS_MOVSX:
    case X86_INS_MOVSXD:
    case X86_INS_MOVUPD:
    case X86_INS_MOVZX:
        map_[*op0] = map_[*op1];
        break;
    case X86_INS_MUL:
        map_[X86_REG_RAX] *= map_[*op0];
        break;
    case X86_INS_NEG:
        map_[*op0].negate();
        break;
    case X86_INS_NOT:
        map_[*op0].invert();
        break;
    case X86_INS_OR:
        map_[*op0] |= map_[*op1];
        break;
    case X86_INS_POP:
        map_[*op0] = map_[map_[X86_REG_RSP].memorize()];
        map_[X86_REG_RSP] += 8i64;
        break;
    case X86_INS_PUSH:
        map_[X86_REG_RSP] -= 0x8i64;
        map_[map_[X86_REG_RSP].memorize()] = map_[*op0];
        break;
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        map_[X86_REG_RIP] = map_[map_[X86_REG_RSP].memorize()];
        map_[X86_REG_RSP] += 8i64;
        break;
    case X86_INS_SHL:
        map_[*op0] <<= map_[*op1];
        break;
    case X86_INS_SHR:
        map_[*op0] >>= map_[*op1];
        break;
    case X86_INS_SUB:
        map_[*op0] -= map_[*op1];
        break;
    case X86_INS_TEST:
        // TODO
        break;
    case X86_INS_XCHG:
        {
            const auto xchg = map_[*op0];
            map_[*op0] = map_[*op1];
            map_[*op1] = xchg;
        }
        break;
    case X86_INS_XOR:
        map_[*op0] ^= map_[*op1];
        break;
    default:
        throw;
    }
}

bool data_flow::empty() const
{
    return map_->empty();
}
size_t data_flow::size() const
{
    return map_->size();
}

std::vector<uint64_t> data_flow::inspect_rip()
{
    std::vector<uint64_t> result;
    for (const auto expr : *map_[X86_REG_RIP])
    {
        const auto value = expr.get_const_value();
        if (value.has_value())
            result.push_back(*value);
    }

    return result;
}

std::vector<std::wstring> data_flow::get_replacement() const
{
    if (!sequence_.has_value())
        throw;

    std::map<x86_reg, std::wstring> reg_map;
    std::map<int64_t, std::wstring> num_map;
    const auto rep = sequence_->get_representation(reg_map, num_map);

    std::vector<std::wstring> result;
    for (const auto& [expr, expr_var] : *map_)
    {
        const auto reg = expr.get_reg_value();
        if (reg.has_value() && *reg != X86_REG_RIP)
        {
            if (*reg == X86_REG_RSP)
            {
                const auto add = (*expr_var).front().get_add_value();
                if (add.has_value())
                {
                    std::wostringstream ss;
                    ss << L"sub rsp, 0x";
                    ss << std::hex << std::uppercase << -*add;
                    result.push_back(ss.str());
                }
                continue;
            }

            const auto num = (*expr_var).front().get_const_value();
            if (num.has_value())
                result.push_back(L"movabs " + reg_map.at(*reg) + L", " + num_map.at(*num));
        }
    }

    return result;
}

bool operator<(const data_flow& flow1, const data_flow& flow2)
{
    if (flow1.map_->size() != flow2.map_->size())
        return flow1.map_->size() < flow2.map_->size();

    auto it1 = flow1.map_->begin();
    auto it2 = flow2.map_->begin();

    // TODO

    return false;
}

bool operator<(const data_flow::expression& expr1, const data_flow::expression& expr2)
{
    return expr1.to_string() < expr2.to_string();
}

data_flow::expression_variant operator/(data_flow::expression_variant expr_var1, const data_flow::expression_variant & expr_var2)
{
    expr_var1 /= expr_var2;
    return expr_var1;
}
data_flow::expression_variant operator%(data_flow::expression_variant expr_var1, const data_flow::expression_variant & expr_var2)
{
    expr_var1 %= expr_var2;
    return expr_var1;
}
