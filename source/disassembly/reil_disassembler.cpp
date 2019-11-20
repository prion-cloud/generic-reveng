#include "reil_disassembler_handle.hpp"

namespace grev
{
    reil_disassembler::reil_disassembler(machine_architecture const architecture) :
        handle_(std::make_unique<handle>(architecture)) { }
    reil_disassembler::~reil_disassembler() = default;

    static std::function<z3_expression (z3_expression const&)>
        get_unary_operation(reil_op_t const& reil_operation)
    {
        switch (reil_operation)
        {
        case I_STR:
            return [](auto const& expression) { return expression; };
        case I_LDM:
//set(ins.c, state[*get(ins.a)]);
            return std::mem_fn(
                static_cast<z3_expression (z3_expression::*)() const>(&z3_expression::operator*));
        case I_NEG:
            return std::mem_fn(
                static_cast<z3_expression (z3_expression::*)() const>(&z3_expression::operator-));
        case I_NOT:
            return std::mem_fn(
                static_cast<z3_expression (z3_expression::*)() const>(&z3_expression::operator~));
        default:
            throw std::logic_error("Bad 1"); // TODO
        }
    }
    static std::function<z3_expression (z3_expression const&, z3_expression const&)>
        get_binary_operation(reil_op_t const& reil_operation)
    {
        switch (reil_operation)
        {
        case I_ADD:
            return std::mem_fn(&z3_expression::operator+);
        case I_SUB:
            return std::mem_fn(
                static_cast<z3_expression (z3_expression::*)(z3_expression const&) const>(&z3_expression::operator-));
        case I_MUL:
            return std::mem_fn(
                static_cast<z3_expression (z3_expression::*)(z3_expression const&) const>(&z3_expression::operator*));
        case I_DIV:
            return std::mem_fn(&z3_expression::operator/);
        case I_MOD:
            return std::mem_fn(&z3_expression::operator%);
        case I_SMUL:
            return std::mem_fn(&z3_expression::smul);
        case I_SDIV:
            return std::mem_fn(&z3_expression::sdiv);
        case I_SMOD:
            return std::mem_fn(&z3_expression::smod);
        case I_SHL:
            return std::mem_fn(&z3_expression::operator<<);
        case I_SHR:
            return std::mem_fn(&z3_expression::operator>>);
        case I_AND:
            return std::mem_fn(&z3_expression::operator&);
        case I_OR:
            return std::mem_fn(&z3_expression::operator|);
        case I_XOR:
            return std::mem_fn(&z3_expression::operator^);
        case I_EQ:
            return std::mem_fn(&z3_expression::operator==);
        case I_LT:
            return std::mem_fn(&z3_expression::operator<);
        default:
            throw std::logic_error("Bad 2"); // TODO
        }
    }

    static z3_expression to_expression(reil_arg_t const& reil_argument)
    {
        switch (reil_argument.type)
        {
        case A_REG:
        case A_TEMP:
            return z3_expression(reil_argument.name);
        case A_CONST:
        case A_LOC:
            return z3_expression(reil_argument.val);
        default:
            throw std::logic_error("Bad 3"); // TODO
        }
    }

    machine_state_update reil_disassembler::operator()(data_section* const data_section) const
    {
        auto const& reil_instructions = handle_->disassemble(data_section);

        machine_state_update update;

        auto step = true;
        for (auto const& reil_instruction : reil_instructions)
        {
            if (reil_instruction.op == I_NONE)
                continue;

            if (reil_instruction.op == I_UNK)
            {
                step = false;
                break;
            }

            if (reil_instruction.op == I_JCC && (reil_instruction.a.type != A_CONST || reil_instruction.a.val != 0))
            {
                update.set_jump(to_expression(reil_instruction.c));

                if (reil_instruction.a.type == A_CONST)
                {
                    step = false;
                    break;
                }

                continue;
            }

            if (reil_instruction.op == I_STM)
            {
                update.set(
                    *z3_expression(reil_instruction.c.val),
                    std::vector
                    {
                        to_expression(reil_instruction.a)
                    },
                    [](auto operands)
                    {
                        return std::move(operands[0]);
                    });
                continue;
            }

            z3_expression key(reil_instruction.c.name);

            std::vector<z3_expression> operands;
            std::function<z3_expression (std::vector<z3_expression> const&)> operation;
            if (reil_instruction.b.type == A_NONE)
            {
                operands =
                {
                    to_expression(reil_instruction.a)
                };

                auto const unary_operation = get_unary_operation(reil_instruction.op);
                operation = [unary_operation](auto const& operands)
                {
                    return unary_operation(operands[0]);
                };
            }
            else
            {
                operands =
                {
                    to_expression(reil_instruction.a),
                    to_expression(reil_instruction.b)
                };

                auto const binary_operation = get_binary_operation(reil_instruction.op);
                operation = [binary_operation](auto const& operands)
                {
                    return binary_operation(operands[0], operands[1]);
                };
            }

            update.set(std::move(key), std::move(operands), std::move(operation));
        }

        if (step)
            update.set_jump(z3_expression(data_section->address));

        return update;
    }
}

static_assert(std::is_destructible_v<grev::reil_disassembler>);

static_assert(!std::is_copy_constructible_v<grev::reil_disassembler>); // TODO
static_assert(!std::is_copy_assignable_v<grev::reil_disassembler>); // TODO

static_assert(!std::is_move_constructible_v<grev::reil_disassembler>); // TODO
static_assert(!std::is_move_assignable_v<grev::reil_disassembler>); // TODO
