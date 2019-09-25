#include <memory>

#include "monitor.hpp"

namespace dec
{
    constexpr std::size_t size = sizeof(std::uint_fast64_t) * CHAR_BIT;

    monitor::monitor() :
        mem_(z3::function("bvmem", context_.bv_sort(size), context_.bv_sort(size))) { }

    instruction_impact monitor::trace(std::vector<reil_inst_t> const& intermediate_instructions)
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

        instruction_impact impact;
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
                set(impact, destination, get(impact, source_1));
                break;
            case I_STM:
                set_mem(impact, destination, get(impact, source_1));
                break;
            case I_LDM:
                set(impact, destination, get_mem(impact, source_1));
                break;
            case I_NEG:
            case I_NOT:
                set(impact, destination, unop.at(op)(get(impact, source_1)));
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
                set(impact, destination, binop.at(op)(get(impact, source_1), get(impact, source_2)));
                break;
            }
        }

        return impact;
    }

    z3::expr monitor::get(instruction_impact const& impact, reil_arg_t const& reil_argument)
    {
        switch (reil_argument.type)
        {
        case A_REG:
        {
            auto const key = create_constant(reil_argument.name);
            if (auto const entry = impact.registers.find(key); entry != impact.registers.end())
                return entry->second;

            return key;
        }
        case A_TEMP:
        {
            auto const key = create_constant(reil_argument.name);
            if (auto const entry = impact.temporary.find(key); entry != impact.temporary.end())
                return entry->second;

            return key;
        }
        case A_CONST:
            return create_value(reil_argument.val);
        default:
            throw std::invalid_argument("Unexpected argument type");
        }
    }
    void monitor::set(instruction_impact& impact, reil_arg_t const& reil_argument, z3::expr const& expression)
    {
        auto const key = context_.bv_const(reil_argument.name, size);

        switch (reil_argument.type)
        {
        case A_REG:
            impact.registers.insert_or_assign(key, expression);
            break;
        case A_TEMP:
            impact.temporary.insert_or_assign(key, expression);
            break;
        default:
            throw std::invalid_argument("Unexpected argument type");
        }
    }

    z3::expr monitor::get_mem(instruction_impact const& impact, reil_arg_t const& reil_argument)
    {
        std::unique_ptr<z3::expr> expression;
        switch (reil_argument.type)
        {
        case A_TEMP:
        {
            auto const key = create_constant(reil_argument.name);
            if (auto const entry = impact.memory.find(key); entry != impact.memory.end())
                expression = std::make_unique<z3::expr>(entry->second);
            else
                expression = std::make_unique<z3::expr>(mem_(key));
            break;
        }
        case A_CONST:
            expression = std::make_unique<z3::expr>(mem_(create_value(reil_argument.val)));
            break;
        default:
            throw std::invalid_argument("Unexpected argument type");
        }

        return *expression;
    }
    void monitor::set_mem(instruction_impact& impact, reil_arg_t const& reil_argument, z3::expr const& expression)
    {
        std::unique_ptr<z3::expr> key;
        switch (reil_argument.type)
        {
        case A_TEMP:
            key = std::make_unique<z3::expr>(impact.temporary.at(create_constant(reil_argument.name)));
            break;
        case A_CONST:
            key = std::make_unique<z3::expr>(create_value(reil_argument.val));
            break;
        default:
            throw std::invalid_argument("Unexpected argument type");
        }

        impact.memory.insert_or_assign(*key, expression);
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
