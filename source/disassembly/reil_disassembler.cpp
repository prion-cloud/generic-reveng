#include <functional>

#include <libopenreil.h>

#include <generic-reveng/disassembly/reil_disassembler.hpp>

namespace grev
{
    static z3::expression get_key(reil_arg_t const& reil_key)
    {
        switch (reil_key.type)
        {
        case A_REG:
        case A_TEMP:
            return z3::expression(std::begin(reil_key.name));
        default:
            throw std::logic_error("Unexpected argument type");
        }
    }

    static std::function<z3::expression (z3::expression)>
        get_unary_operation(reil_op_t const& operation)
    {
        switch (operation)
        {
        case I_NEG:
            return std::mem_fn(&z3::expression::operator-);
        case I_NOT:
            return std::mem_fn(&z3::expression::operator~);
        default:
            throw std::logic_error("Unexpected operation");
        }
    }
    static std::function<z3::expression (z3::expression, z3::expression)>
        get_binary_operation(reil_op_t const& operation)
    {
        switch (operation)
        {
        case I_ADD:
            return z3::operator+;
        case I_SUB:
            return z3::operator-;
        case I_MUL:
            return z3::operator*;
        case I_DIV:
            return z3::operator/;
        case I_MOD:
            return z3::operator%;
        case I_SHL:
            return z3::operator<<;
        case I_SHR:
            return z3::operator>>;
        case I_AND:
            return z3::operator&;
        case I_OR:
            return z3::operator|;
        case I_XOR:
            return z3::operator^;
        case I_EQ:
            return std::mem_fn(&z3::expression::equals);
        case I_LT:
            return std::mem_fn(&z3::expression::less_than);
        default:
            throw std::logic_error("Unexpected operation");
        }
    }

    reil_disassembler::reil_disassembler(machine_architecture architecture) :
        architecture_(std::move(architecture))
    {
        reil_arch_t converted_architecture;
        switch (architecture_)
        {
            case machine_architecture::x86_32:
                converted_architecture = ARCH_X86;
                break;
            default:
                throw std::runtime_error("Unexpected architecture");
        }
        handle_ = reil_init(
            converted_architecture,
            [](auto* const instruction, auto* const instructions)
            {
                static_cast<std::list<reil_inst_t>*>(instructions)->push_back(*instruction);
                return 0;
            },
            &instructions_);
    }
    reil_disassembler::~reil_disassembler()
    {
        reil_close(handle_);
    }

    reil_disassembler::reil_disassembler(reil_disassembler const& other) :
        reil_disassembler(other.architecture_) { }
    reil_disassembler::reil_disassembler(reil_disassembler&& other) noexcept :
        architecture_(std::move(other.architecture_)),
        handle_(std::exchange(other.handle_, nullptr)) { }

    reil_disassembler& reil_disassembler::operator=(reil_disassembler other) noexcept
    {
        std::swap(architecture_, other.architecture_);
        std::swap(handle_, other.handle_);

        return *this;
    }

    execution_update reil_disassembler::operator()(std::uint32_t* const address, std::u8string_view* const code) const
    {
        std::vector<unsigned char> narrowed_code(
            code->begin(),
            std::next(
                code->begin(),
                std::min(code->size(), std::size_t{MAX_INST_LEN})));

        instructions_.clear();
        reil_translate_insn(handle_, *address, narrowed_code.data(), narrowed_code.size());

        auto const size = instructions_.front().raw_info.size;

        *address += size;
        code->remove_prefix(size);

        std::optional<std::uint64_t> step_value{*address};
        for (auto const& instruction : instructions_)
        {
            switch (instruction.op)
            {
            case I_NONE:
                break;
            case I_UNK:
                step_value = *address - size + 1;
                break;
            case I_JCC:
                if (instruction.a.type == A_CONST)
                {
                    if (instruction.a.val == 0)
                        break;
                    step_value = std::nullopt;
                }
                update_.jumps.insert(get_value(instruction.c));
                break;
            case I_STR:
                set_value(instruction.c, get_value(instruction.a));
                break;
            case I_STM:
                update_.state.define(get_value(instruction.c).dereference(), get_value(instruction.a));
                break;
            case I_LDM:
                set_value(instruction.c, update_.state[get_value(instruction.a)].dereference());
                break;
            default:
                if (instruction.b.type == A_NONE)
                {
                    auto const unary_operation = get_unary_operation(instruction.op);
                    set_value(instruction.c, unary_operation(get_value(instruction.a)));
                }
                else
                {
                    auto const binary_operation = get_binary_operation(instruction.op);
                    set_value(instruction.c, binary_operation(get_value(instruction.a), get_value(instruction.b)));
                }
                break;
            }

            if (!step_value)
                break;
        }

        if (step_value)
            update_.jumps.emplace(*step_value);

        temporary_state_.clear();
        return std::move(update_);
    }

    z3::expression reil_disassembler::get_value(reil_arg_t const& argument) const
    {
        switch (argument.type)
        {
        case A_REG:
            return update_.state[get_key(argument)];
        case A_TEMP:
            return temporary_state_[get_key(argument)];
        case A_CONST:
        case A_LOC: // TODO Prohibit inum
            return z3::expression(argument.val);
        default:
            throw std::logic_error("Unexpected argument type");
        }
    }
    void reil_disassembler::set_value(reil_arg_t const& argument, z3::expression value) const
    {
        switch (argument.type)
        {
        case A_REG:
            update_.state.define(get_key(argument), std::move(value));
            break;
        case A_TEMP:
            temporary_state_.define(get_key(argument), std::move(value));
            break;
        default:
            throw std::logic_error("Unexpected argument type");
        }
    }
}

static_assert(std::is_destructible_v<grev::reil_disassembler>);

static_assert(std::is_copy_constructible_v<grev::reil_disassembler>);
static_assert(std::is_nothrow_move_constructible_v<grev::reil_disassembler>);

static_assert(std::is_copy_assignable_v<grev::reil_disassembler>);
static_assert(std::is_nothrow_move_assignable_v<grev::reil_disassembler>);
