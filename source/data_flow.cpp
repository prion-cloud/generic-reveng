#include <optional>
#include <sstream>

#include "data_flow.h"

template <char C>
data_entry::expr_unop<C>::expr_unop(const expr& next)
{
    // TODO
}

template <char C>
data_entry::expr_binop<C>::expr_binop(const expr& left, const expr& right)
{
    // TODO
}

template <char C>
data_entry::expr_assop<C>::expr_assop(const std::vector<expr>& next)
{
    // TODO
}

data_entry::expr_reg::expr_reg(const x86_reg& reg)
    : reg(reg)
{
    csh cs;
    cs_open(CS_ARCH_X86, CS_MODE_64, &cs);

    str = cs_reg_name(cs, reg);

    cs_close(&cs);
}
data_entry::expr_imm::expr_imm(const uint64_t& imm)
    : imm(imm)
{
    std::ostringstream ss;
    ss << std::hex << std::uppercase << imm;

    str = ss.str();
}
data_entry::expr_mem::expr_mem(const expr& mem)
    : mem(mem)
{
    str = "[" + mem.str + "]";
}
data_entry::expr_fp::expr_fp(const double& fp)
    : fp(fp)
{
    str = std::to_string(fp);
}

data_entry::data_entry(const x86_reg& reg)
    : data_entry({ expr_reg(reg) }) { }
data_entry::data_entry(const uint64_t& imm)
    : data_entry({ expr_imm(imm) }) { }
data_entry::data_entry(const double& fp)
    : data_entry({ expr_fp(fp) }) { }

const std::string& data_entry::str() const
{
    return str_;
}

void data_entry::concat(const data_entry& other)
{
    base_.insert(base_.end(), other.base_.begin(), other.base_.end());
}

void data_entry::memorize()
{
    modify_all([](const expr e) { return expr_mem(e); });
}

void data_entry::negate()
{
    modify_all([](const expr e) { return expr_unop<'-'>(e); });
}
void data_entry::invert()
{
    modify_all([](const expr e) { return expr_unop<'~'>(e); });
}

void data_entry::operator+=(const data_entry& other)
{
    modify_all([other](const expr e1, const expr e2) { return expr_assop<'+'>({ e1, e2 }); }, other);
}
void data_entry::operator-=(const data_entry& other)
{
    modify_all([other](const expr e1, const expr e2) { return expr_assop<'+'>({ e1, e2 }); }, -other);
}
void data_entry::operator*=(const data_entry& other)
{
    modify_all([other](const expr e1, const expr e2) { return expr_assop<'*'>({ e1, e2 }); }, other);
}
void data_entry::operator/=(const data_entry& other)
{
    modify_all([other](const expr e1, const expr e2) { return expr_binop<'/'>(e1, e2); }, other);
}
void data_entry::operator%=(const data_entry& other)
{
    modify_all([other](const expr e1, const expr e2) { return expr_binop<'%'>(e1, e2); }, other);
}

void data_entry::operator&=(const data_entry& other)
{
    modify_all([other](const expr e1, const expr e2) { return expr_binop<'&'>(e1, e2); }, other);
}
void data_entry::operator|=(const data_entry& other)
{
    modify_all([other](const expr e1, const expr e2) { return expr_binop<'|'>(e1, e2); }, other);
}
void data_entry::operator^=(const data_entry& other)
{
    modify_all([other](const expr e1, const expr e2) { return expr_binop<'^'>(e1, e2); }, other);
}

void data_entry::operator<<=(const data_entry& other)
{
    modify_all([other](const expr e1, const expr e2) { return expr_binop<'&'>(e1, e2); }, other);
}
void data_entry::operator>>=(const data_entry& other)
{
    throw std::runtime_error("TODO");
}

bool data_entry::operator==(const data_entry& other) const
{
    return str_ == other.str_;
}

data_entry::data_entry(const std::vector<expr>& base)
    : base_(base)
{
    update_str();
}

void data_entry::update_str()
{
    std::ostringstream ss;
    for (unsigned i = 0; i < base_.size(); ++i)
    {
        if (i > 0)
            ss << " : ";

        ss << base_.at(i).str;
    }

    str_ = ss.str();
}

void data_entry::modify_all(const std::function<expr(expr)>& func)
{
}
void data_entry::modify_all(const std::function<expr(expr, expr)>& func, const data_entry& other)
{
    std::vector<expr> base;
    for (const auto& expr1 : base_)
    {
        for (const auto& expr2 : other.base_)
            base.push_back(func(expr1, expr2));
    }

    base_ = base;

    update_str();
}

data_entry data_entry::operator-() const
{
    data_entry entry(base_);
    entry.negate();
    return entry;
}

std::size_t data_flow::data_entry_hash::operator()(const data_entry& entry) const
{
    return std::hash<std::string>()(entry.str());
}

std::vector<std::string> data_flow::data_map::str() const
{
    std::vector<std::string> result;
    for (const auto&[container, entry] : base_)
        result.push_back(container.str() + " <- " + entry.str());

    return result;
}

data_entry data_flow::data_map::effect(const x86_op_mem& mem, const bool& memorize)
{
    data_entry entry = static_cast<uint64_t>(mem.disp);

    if (mem.base != X86_REG_INVALID)
        entry += operator[](static_cast<x86_reg>(mem.base));

    if (mem.index != X86_REG_INVALID)
    {
        auto sub = operator[](static_cast<x86_reg>(mem.index));
        sub *= static_cast<uint64_t>(mem.scale);
        entry += sub;
    }

    if (memorize)
        entry.memorize();

    return entry;
}

data_entry& data_flow::data_map::operator[](const data_entry& container)
{
    if (base_.find(container) == base_.end())
        base_.emplace(container, container);

    return base_.at(container);
}
data_entry& data_flow::data_map::operator[](const cs_x86_op& operand)
{
    switch (operand.type)
    {
    case X86_OP_REG:
        return operator[](operand.reg);
    case X86_OP_IMM:
        return operator[](static_cast<uint64_t>(operand.imm));
    case X86_OP_MEM:
        return operator[](effect(operand.mem, true));
    case X86_OP_FP:
        return operator[](operand.fp);
    default:
        throw std::runtime_error("Bad operand");
    }
}

std::vector<std::pair<data_entry, data_entry>> data_flow::data_map::operator*() const
{
    std::vector<std::pair<data_entry, data_entry>> result;
    for (const auto& [container, content] : base_)
    {
        if (container == content)
            continue;

        if (container == X86_REG_RIP)
            continue;

        result.emplace_back(container, content);
    }

    return result;
}

std::vector<std::string> data_flow::str() const
{
    return map_.str();
}

std::vector<std::pair<data_entry, data_entry>> data_flow::status() const
{
    return *map_;
}

static cs_x86_op to_operator(const x86_reg& reg)
{
    return cs_x86_op{ X86_OP_REG, reg };
}

void data_flow::commit(const cs_insn& instruction)
{
    const auto detail = instruction.detail->x86;

    if (detail.op_count > 2)
        throw std::runtime_error("Too many operands");

    std::optional<cs_x86_op> op0 = std::nullopt;
    if (detail.op_count > 0)
        op0 = detail.operands[0];

    std::optional<cs_x86_op> op1 = std::nullopt;
    if (detail.op_count > 1)
        op1 = detail.operands[1];

    map_[X86_REG_RIP] = instruction.address + instruction.size;

    switch (instruction.id)
    {
    case X86_INS_NEG:
        map_[*op0].negate();
        break;
    case X86_INS_NOT:
        map_[*op0].invert();
        break;
    case X86_INS_ADD:
        map_[*op0] += map_[*op1];
        break;
    case X86_INS_SUB:
        map_[*op0] -= map_[*op1];
        break;
    case X86_INS_IMUL:
        if (op1.has_value())
        {
            map_[*op0] *= map_[*op1];
            break;
        }
    case X86_INS_MUL:
        map_[X86_REG_RAX] *= map_[*op0];
        break;
    case X86_INS_IDIV:
    case X86_INS_DIV:
    {
        const auto dividend = map_[X86_REG_RAX];
        map_[X86_REG_RAX] = dividend / map_[*op0];
        map_[X86_REG_RDX] = dividend % map_[*op0];
        break;
    }
    case X86_INS_AND:
        map_[*op0] &= map_[*op1];
        break;
    case X86_INS_OR:
        map_[*op0] |= map_[*op1];
        break;
    case X86_INS_XOR:
        map_[*op0] ^= map_[*op1];
        break;
    case X86_INS_SAL:
    case X86_INS_SHL:
        map_[*op0] <<= map_[*op1];
        break;
    case X86_INS_SHR:
        map_[*op0] >>= map_[*op1];
        break;
    case X86_INS_MOV:
    case X86_INS_MOVABS:
    case X86_INS_MOVSX:
    case X86_INS_MOVSXD:
    case X86_INS_MOVUPD:
    case X86_INS_MOVZX:
        map_[*op0] = map_[*op1];
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
    case X86_INS_XCHG:
    {
        const auto xchg = map_[*op0];
        map_[*op0] = map_[*op1];
        map_[*op1] = xchg;
        break;
    }
    case X86_INS_LEA:
        map_[*op0] = map_.effect(op1->mem, false);
        break;
    case X86_INS_JMP:
        map_[X86_REG_RIP] = map_[*op0];
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
    case X86_INS_CALL:
    {
        const auto rip = map_[X86_REG_RIP];
        map_[X86_REG_RIP] = map_[*op0];
        //op0 = to_operator(rip);
    }
    case X86_INS_PUSH:
        map_[X86_REG_RSP] -= 0x8ui64;
        map_[memorize(map_[X86_REG_RSP])] = map_[*op0];
        break;
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        op0 = to_operator(X86_REG_RIP);
    case X86_INS_POP:
        map_[*op0] = map_[memorize(map_[X86_REG_RSP])];
        map_[X86_REG_RSP] += 0x8ui64;
        break;
    default:
        throw std::runtime_error("Unknown instruction");
    }
}

data_entry data_flow::memorize(data_entry entry)
{
    entry.memorize();
    return entry;
}

data_entry operator/(data_entry first, const data_entry& second)
{
    first /= second;
    return first;
}
data_entry operator%(data_entry first, const data_entry& second)
{
    first %= second;
    return first;
}
