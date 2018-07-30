#include <optional>
#include <sstream>

#include "data_monitor.h"

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
/*
data_entry::data_entry(const x86_reg& reg)
    : data_entry({ expr_reg(reg) }) { }
data_entry::data_entry(const uint64_t& imm)
    : data_entry({ expr_imm(imm) }) { }
data_entry::data_entry(const double& fp)
    : data_entry({ expr_fp(fp) }) { }
*/
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

std::size_t data_monitor::data_entry_hash::operator()(const data_entry& entry) const
{
    return std::hash<std::string>()(entry.str());
}

/*
data_entry data_monitor::data_map::parse(data_source const& source, std::vector<cs_x86_op> const& operands) const
{
    if (!source.op.has_value())
        return source.operands.front()
}

data_entry& data_monitor::data_map::operator[](data_destination const& destination)
{
    destination.
}


data_entry data_monitor::data_map::effect(const x86_op_mem& mem, const bool& memorize)
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

data_entry& data_monitor::data_map::operator[](const data_entry& container)
{
    if (base_.find(container) == base_.end())
        base_.emplace(container, container);

    return base_.at(container);
}
data_entry& data_monitor::data_map::operator[](const cs_x86_op& operand)
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
*/

std::vector<std::pair<data_entry, data_entry>> data_monitor::data_map::operator*() const
{
    std::vector<std::pair<data_entry, data_entry>> result;
    for (const auto& [container, content] : base_)
    {
        if (container == content)
            continue;

        /*if (container == X86_REG_RIP)
            continue;*/

        result.emplace_back(container, content);
    }

    return result;
}

data_monitor::data_monitor(const data_ir& ir)
    : ir_(ir) { }

std::vector<std::pair<data_entry, data_entry>> data_monitor::status() const
{
    return *map_;
}

std::string data_monitor::commit(const cs_insn& instruction)
{
    /*
    auto const detail = instruction.detail->x86; // TODO: x86

    for (auto const& flow : ir_[instruction.id])
    {
        //map_[flow] = map_.parse(flow.source,
        //    std::vector<cs_x86_op>(detail.operands, detail.operands + detail.op_count));
    }
    */
    return { };
}
