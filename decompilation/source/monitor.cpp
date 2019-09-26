#include <memory>

#include "monitor.hpp"

namespace dec
{
    constexpr std::size_t size = sizeof(std::uint_fast64_t) * CHAR_BIT;

    monitor::monitor() :
        mem_(z3::function("bvmem", context_.bv_sort(size), context_.bv_sort(size))) { }

    std::unordered_map<z3::expr, z3::expr> monitor::trace(std::vector<reil_inst_t> const& intermediate_instructions)
    {
        static std::unordered_map<reil_op_t, z3::expr (*)(z3::expr const&)> const unop
        {
            { I_NEG, z3::operator- },
            { I_NOT, z3::operator~ }
        };
        static std::unordered_map<reil_op_t, z3::expr (*)(z3::expr const&, z3::expr const&)> const binop
        {
            { I_ADD, z3::operator+ },
            { I_SUB, z3::operator- },
            { I_MUL, z3::operator* },
            { I_DIV, z3::operator/ },
            { I_MOD, z3::mod },
            { I_SMUL, z3::operator* }, // TODO
            { I_SDIV, z3::operator/ }, // TODO
            { I_SMOD, z3::mod }, // TODO
            { I_SHL, z3::shl },
            { I_SHR, z3::lshr },
            { I_AND, z3::operator& },
            { I_OR, z3::operator| },
            { I_XOR, z3::operator^ },
            { I_EQ, z3::operator== },
            { I_LT, z3::operator< }
        };

        for (auto const& reil_instruction : intermediate_instructions)
        {
            auto const op = reil_instruction.op;

            auto const source_1 = reil_instruction.a;
            auto const source_2 = reil_instruction.b;

            auto const destination = reil_instruction.c;

            switch (op)
            {
            case I_NONE:
            case I_UNK:
            case I_JCC:
                break;
            case I_STR:
                set(destination, get(source_1));
                break;
            case I_STM:
                set_mem(destination, get(source_1));
                break;
            case I_LDM:
                set(destination, get_mem(source_1));
                break;
            case I_NEG:
            case I_NOT:
                set(destination, unop.at(op)(get(source_1)).simplify());
                break;
            case I_ADD:
            case I_SUB:
            case I_MUL:
            case I_DIV:
            case I_MOD:
            case I_SMUL:
            case I_SDIV:
            case I_SMOD:
            case I_SHL:
            case I_SHR:
            case I_AND:
            case I_OR:
            case I_XOR:
            case I_EQ:
            case I_LT:
                set(destination, binop.at(op)(get(source_1), get(source_2)).simplify());
                break;
            }
        }

        return std::move(impact_);
    }

    z3::expr monitor::get(reil_arg_t const& source)
    {
        switch (source.type)
        {
        case A_REG:
        {
            auto const key = create_constant(source.name);
            if (auto const entry = impact_.find(key); entry != impact_.end())
                return entry->second;
            return key;
        }
        case A_TEMP:
            // There are no unbound temporaries
            return impact_temporary_.at(source.name);
        case A_CONST:
            return create_value(source.val);
        default:
            throw std::invalid_argument("Unexpected argument type");
        }
    }
    z3::expr monitor::get_mem(reil_arg_t const& source)
    {
        switch (source.type)
        {
        case A_TEMP:
        {
            auto const key = mem_(get(source));
            if (auto const entry = impact_.find(key); entry != impact_.end())
                return entry->second;
            return key;
        }
        case A_CONST:
            return mem_(get(source));
        default:
            throw std::invalid_argument("Unexpected argument type");
        }
    }

    void monitor::set(reil_arg_t const& destination, z3::expr const& expression)
    {
        switch (destination.type)
        {
        case A_REG:
            impact_.insert_or_assign(create_constant(destination.name), expression);
            break;
        case A_TEMP:
            impact_temporary_.insert_or_assign(destination.name, expression);
            break;
        default:
            throw std::invalid_argument("Unexpected argument type");
        }
    }
    void monitor::set_mem(reil_arg_t const& destination, z3::expr const& expression)
    {
        impact_.insert_or_assign(mem_(get(destination)), expression);
    }

    z3::expr monitor::create_constant(std::string const& name)
    {
        return context_.bv_const(name.c_str(), size);
    }
    z3::expr monitor::create_value(std::uint_fast64_t const value)
    {
        return context_.bv_val(value, size);
    }

    static_assert(std::is_destructible_v<monitor>);

    static_assert(!std::is_move_constructible_v<monitor>); // TODO
    static_assert(!std::is_move_assignable_v<monitor>); // TODO

    static_assert(!std::is_copy_constructible_v<monitor>); // TODO
    static_assert(!std::is_copy_assignable_v<monitor>); // TODO
}
