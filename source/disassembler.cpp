#include "disassembler_handle.hpp"

namespace dec
{
    disassembler::disassembler(instruction_set_architecture const architecture) :
        handle_(std::make_unique<handle>(architecture)) { }
    disassembler::~disassembler() = default;

    instruction disassembler::operator()(data_section const& data_section) const
    {
        auto const& reil_instructions = handle_->disassemble(data_section);

        instruction instruction
        {
            .address = data_section.address,
            .size = static_cast<std::uint64_t>(reil_instructions.front().raw_info.size)
        };

        expression_composition temporary;

        auto const get = [this, &instruction, &temporary](reil_arg_t const& source)
        {
            switch (source.type)
            {
            case A_REG:
                return instruction.impact[source.name];
            case A_TEMP:
                return temporary[source.name];
            case A_CONST:
            case A_LOC:
                // TODO prohibit inum
                return expression(source.val);
            default:
                throw std::invalid_argument("Unexpected argument type");
            }
        };
        auto const set = [this, &instruction, &temporary](reil_arg_t const& destination, expression const& value)
        {
            switch (destination.type)
            {
            case A_REG:
                instruction.impact[destination.name] = value;
                break;
            case A_TEMP:
                temporary[destination.name] = value;
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
                instruction.jump.clear();
                step = false;
                break;
            case I_JCC:
                instruction.jump.insert(get(ins.c));
                if (ins.a.type == A_CONST && ins.a.val != 0)
                    step = false;
                break;
            case I_STR:
                set(ins.c, get(ins.a));
                break;
            case I_STM:
                instruction.impact[get(ins.c).mem()] = get(ins.a);
                break;
            case I_LDM:
                set(ins.c, instruction.impact[get(ins.a).mem()]);
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
                set(ins.c, get(ins.a) * get(ins.b));
                break;
            case I_DIV:
                set(ins.c, get(ins.a) / get(ins.b));
                break;
            case I_MOD:
                set(ins.c, get(ins.a) % get(ins.b));
                break;
//            case I_SMUL:
//            case I_SDIV:
//            case I_SMOD:
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
                set(ins.c, get(ins.a).eq(get(ins.b)));
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
            instruction.jump.insert(expression(instruction.address + instruction.size));

        return instruction;
    }

    static_assert(std::is_destructible_v<disassembler>);

    static_assert(!std::is_move_constructible_v<disassembler>); // TODO
    static_assert(!std::is_move_assignable_v<disassembler>); // TODO

    static_assert(!std::is_copy_constructible_v<disassembler>); // TODO
    static_assert(!std::is_copy_assignable_v<disassembler>); // TODO
}
