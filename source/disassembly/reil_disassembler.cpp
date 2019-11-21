#include <cstdint>

#include <libopenreil.h>

#include <generic-reveng/disassembly/reil_disassembler.hpp>

namespace grev
{
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
            throw std::logic_error("Unexpected argument type"); // TODO
        }
    }

    static std::function<z3_expression (z3_expression)>
        get_key_operation(reil_op_t const& reil_operation)
    {
        switch (reil_operation)
        {
        case I_STM:
            return std::mem_fn(static_cast<z3_expression (z3_expression::*)() const>(&z3_expression::operator*));
        default:
            return { };
        }
    }

    static std::function<z3_expression (z3_expression)>
        get_unary_operation(reil_op_t const& reil_operation)
    {
        switch (reil_operation)
        {
        case I_STR:
        case I_STM:
            return [](auto operand) { return std::move(operand); };
        case I_LDM:
            return std::mem_fn(static_cast<z3_expression (z3_expression::*)() const>(&z3_expression::operator*));
        case I_NEG:
            return std::mem_fn(static_cast<z3_expression (z3_expression::*)() const>(&z3_expression::operator-));
        case I_NOT:
            return std::mem_fn(static_cast<z3_expression (z3_expression::*)() const>(&z3_expression::operator~));
        default:
            throw std::logic_error("Unexpected operation");
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
            throw std::logic_error("Unexpected operation");
        }
    }

    static std::pair<machine_state_update_part, bool> translate(reil_inst_t const& reil_instruction)
    {
        std::pair<machine_state_update_part, bool> translation;
        auto& [part, step] = translation;

        part.key_operation = get_key_operation(reil_instruction.op);

        if (reil_instruction.op == I_JCC)
        {
            part.key = std::nullopt;
            part.operands.push_back(to_expression(reil_instruction.c));
            part.value_operation = [](auto operands)
            {
                return std::move(operands[0]);
            };

            step = reil_instruction.a.type != A_CONST;

            return translation;
        }

        part.key = to_expression(reil_instruction.c),
        part.operands.push_back(to_expression(reil_instruction.a));

        step = true;

        if (reil_instruction.b.type == A_NONE)
        {
            auto const unary_operation = get_unary_operation(reil_instruction.op);
            part.value_operation = [unary_operation](auto operands)
            {
                return unary_operation(std::move(operands[0]));
            };

            return translation;
        }

        part.operands.push_back(to_expression(reil_instruction.b));

        auto const binary_operation = get_binary_operation(reil_instruction.op);
        part.value_operation = [binary_operation](auto operands)
        {
            return binary_operation(std::move(operands[0]), std::move(operands[1]));
        };

        return translation;
    }

    reil_disassembler::reil_disassembler(machine_architecture const architecture)
    {
        reil_arch_t reil_architecture;
        switch (architecture)
        {
            case machine_architecture::x86_32:
            case machine_architecture::x86_64:
                reil_architecture = ARCH_X86;
                break;
            default:
                throw std::runtime_error("Unknown architecture");
        }

        reil_ = reil_init(
            reil_architecture,
            [](auto* const reil_instruction, auto* const reil_instructions)
            {
                static_cast<std::vector<reil_inst_t>*>(reil_instructions)->push_back(*reil_instruction);
                return 0;
            },
            &current_reil_instructions_);
    }
    reil_disassembler::~reil_disassembler()
    {
        reil_close(reil_);
    }

    machine_state_update reil_disassembler::operator()(data_section* const data_section) const
    {
        auto reil_instructions = disassemble(*data_section);

        auto const size = reil_instructions.front().raw_info.size;
        data_section->address += size;
        data_section->data.remove_prefix(size);

        machine_state_update update;

        while (true)
        {
            auto step = true;

            for (auto const& reil_instruction : reil_instructions)
            {
                if (reil_instruction.op == I_NONE)
                    continue;
                if (reil_instruction.op == I_JCC && reil_instruction.a.type == A_CONST && reil_instruction.a.val == 0)
                    continue;

                if (reil_instruction.op == I_UNK)
                {
                    step = false;
                    break;
                }

                machine_state_update_part part;
                std::tie(part, step) = translate(reil_instruction);

                update.set(std::move(part));

                if (!step)
                    break;
            }

            if (!step)
                break;

            reil_inum_t const inum = reil_instructions.back().inum + 1;

            reil_instructions =
            {
                reil_inst_t
                {
                    .inum = inum,
                    .op = I_JCC,
                    .a =
                    {
                        .type = A_CONST,
                        .size = U1, // TODO
                        .val = 1
                    },
                    .c =
                    {
                        .type = A_CONST,
                        .size = U64, // TODO
                        .val = data_section->address
                    }
                }
            };
        }

        return update;
    }

    std::vector<reil_inst_t> reil_disassembler::disassemble(data_section const& data_section) const
    {
        std::vector<unsigned char> code(
            data_section.data.begin(),
            std::next(
                data_section.data.begin(),
                std::min(data_section.data.size(), std::size_t{MAX_INST_LEN})));

        reil_translate_insn(reil_, data_section.address, code.data(), code.size());
        return std::move(current_reil_instructions_);
    }
}

static_assert(std::is_destructible_v<grev::reil_disassembler>);

static_assert(std::is_copy_constructible_v<grev::reil_disassembler>);
static_assert(std::is_move_constructible_v<grev::reil_disassembler>);

static_assert(std::is_copy_assignable_v<grev::reil_disassembler>);
static_assert(std::is_move_assignable_v<grev::reil_disassembler>);
