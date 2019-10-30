#include "reil_disassembler_handle.hpp"

namespace rev::dis
{
    reil_disassembler::reil_disassembler(machine_architecture const architecture) :
        handle_(std::make_unique<handle>(architecture)) { }
    reil_disassembler::~reil_disassembler() = default;

    machine_impact reil_disassembler::operator()(data_section* const data_section) const
    {
        auto const& reil_instructions = handle_->disassemble(data_section);

        machine_impact impact;
        machine_impact temporary_impact;

        auto const get = [this, &impact, &temporary_impact](reil_arg_t const& source)
        {
            switch (source.type)
            {
            case A_REG:
                return impact[source.name];
            case A_TEMP:
                return temporary_impact[source.name];
            case A_CONST:
            case A_LOC:
                // TODO prohibit inum
                return expression::value(source.val);
            default:
                throw std::invalid_argument("Unexpected argument type");
            }
        };
        auto const set = [this, &impact, &temporary_impact](reil_arg_t const& destination, expression const& value)
        {
            switch (destination.type)
            {
            case A_REG:
                impact[destination.name] = value;
                break;
            case A_TEMP:
                temporary_impact[destination.name] = value;
                break;
            default:
                throw std::invalid_argument("Unexpected argument type");
            }
        };

        auto step = true;
        for (auto const& ins : reil_instructions)
        {
            // TODO switch for source (expression const&) and dest (expression&)
            switch (ins.op)
            {
            case I_NONE:
                break;
            case I_UNK:
                step = false;
                break;
            case I_JCC:
                impact.jump(get(ins.c));
                if (ins.a.type == A_CONST && ins.a.val != 0)
                    step = false;
                break;
            case I_STR:
                set(ins.c, get(ins.a));
                break;
            case I_STM:
                impact[get(ins.c).mem()] = get(ins.a);
                break;
            case I_LDM:
                set(ins.c, impact[get(ins.a).mem()]);
                break;
            case I_NEG:
                set(ins.c, -get(ins.a));
                break;
            case I_NOT:
                set(ins.c, ~get(ins.a));
                break;
            case I_ADD:
                set(ins.c, get(ins.a) + get(ins.b));
                break;
            case I_SUB:
                set(ins.c, get(ins.a) - get(ins.b));
                break;
            case I_MUL:
            case I_SMUL: // TODO
                set(ins.c, get(ins.a) * get(ins.b));
                break;
            case I_DIV:
            case I_SDIV: // TODO
                set(ins.c, get(ins.a) / get(ins.b));
                break;
            case I_MOD:
            case I_SMOD: // TODO
                set(ins.c, get(ins.a) % get(ins.b));
                break;
            case I_SHL:
                set(ins.c, get(ins.a) << get(ins.b));
                break;
            case I_SHR:
                set(ins.c, get(ins.a) >> get(ins.b));
                break;
            case I_AND:
                set(ins.c, get(ins.a) & get(ins.b));
                break;
            case I_OR:
                set(ins.c, get(ins.a) | get(ins.b));
                break;
            case I_XOR:
                set(ins.c, get(ins.a) ^ get(ins.b));
                break;
            case I_EQ:
                set(ins.c, get(ins.a) == (get(ins.b)));
                break;
            case I_LT:
                set(ins.c, get(ins.a) < get(ins.b));
                break;
            default:
                throw std::invalid_argument("Unexpected operation type");
            }

            if (!step)
                break;
        }

        if (step)
            impact.jump(expression::value(data_section->address + data_section->data.size()));

        return impact;
    }

    static_assert(std::is_destructible_v<reil_disassembler>);

    static_assert(!std::is_move_constructible_v<reil_disassembler>); // TODO
    static_assert(!std::is_move_assignable_v<reil_disassembler>); // TODO

    static_assert(!std::is_copy_constructible_v<reil_disassembler>); // TODO
    static_assert(!std::is_copy_assignable_v<reil_disassembler>); // TODO
}
