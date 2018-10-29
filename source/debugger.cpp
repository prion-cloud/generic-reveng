#include <sstream>

#include "../include/follower/debugger.h"
#include "../include/follower/loader.h"

#define CS_FATAL(cs_method_call)                            \
{                                                           \
    cs_err const error_code = cs_method_call;               \
                                                            \
    if (error_code != CS_ERR_OK)                            \
    {                                                       \
        std::ostringstream oss_error;                       \
        oss_error                                           \
            << cs_strerror(error_code)                      \
            << " @ \"" << #cs_method_call << "\""           \
            << " @ " << __FILE__                            \
            << " @ " << __LINE__;                           \
                                                            \
        throw std::runtime_error(oss_error.str());          \
    }                                                       \
}
#define UC_FATAL(uc_method_call)                            \
{                                                           \
    uc_err const error_code = uc_method_call;               \
                                                            \
    if (error_code != UC_ERR_OK)                            \
    {                                                       \
        std::ostringstream oss_error;                       \
        oss_error                                           \
            << uc_strerror(error_code)                      \
            << " @ \"" << #uc_method_call << "\""           \
            << " @ " << __FILE__                            \
            << " @ " << __LINE__;                           \
                                                            \
        throw std::runtime_error(oss_error.str());          \
    }                                                       \
}

bool operator<(const uc_mem_region a, const uc_mem_region b)
{
    return a.end <= b.begin;
}

uint64_t debugger::position() const
{
    return read_register(ip_register_);
}
bool debugger::position(uint64_t const address) const
{
    write_register(ip_register_, address);

    return is_mapped();
}

bool debugger::is_mapped() const
{
    return is_mapped(position());
}
bool debugger::is_mapped(uint64_t const address) const
{
    auto const memory_regions = get_memory_regions();

    uc_mem_region const comparison_memory_region = { address, address, UC_PROT_NONE };

    return
        memory_regions.lower_bound(comparison_memory_region) !=
        memory_regions.upper_bound(comparison_memory_region);
}

bool debugger::skip() const
{
    return skip(disassemble().code.size());
}
bool debugger::skip(uint64_t const count) const
{
    return position(position() + count);
}

bool debugger::step_into() const
{
    return uc_emu_start(uc_.get(), position(), 0, 0, 1) == UC_ERR_OK;
}
bool debugger::step_over() const
{
    auto const instruction = disassemble();

    if (instruction.groups.count(CS_GRP_CALL) == 0)
        return step_into();

    return uc_emu_start(uc_.get(),
        instruction.address,
        instruction.address + instruction.code.size(), 0, 0) == UC_ERR_OK;
}

instruction debugger::disassemble() const
{
    return disassemble(position());
}
instruction debugger::disassemble(uint64_t const address) const
{
    std::vector<uint8_t> code_buffer(0x10);
    read_memory(address, code_buffer);

    cs_insn* cs_instructions;
    cs_disasm(*cs_, &code_buffer.front(), code_buffer.size(), address, 1, &cs_instructions);

    CS_FATAL(get_cs_error());

    instruction instruction(cs_instructions[0]); // NOLINT

    cs_free(cs_instructions, 1);

    return instruction;
}

std::istream& operator>>(std::istream& is, debugger& debugger)
{
    auto const spec = load(is);

    if (is.fail())
        return is;

    int ip_register;
    int sp_register;
    int bp_register;

    switch (spec.machine_architecture.second)
    {
    case UC_ARCH_X86:
        switch (spec.machine_mode.second)
        {
        case UC_MODE_16:
            ip_register = UC_X86_REG_IP;
            sp_register = UC_X86_REG_SP;
            bp_register = UC_X86_REG_BP;
            break;
        case UC_MODE_32:
            ip_register = UC_X86_REG_EIP;
            sp_register = UC_X86_REG_ESP;
            bp_register = UC_X86_REG_EBP;
            break;
        case UC_MODE_64:
            ip_register = UC_X86_REG_RIP;
            sp_register = UC_X86_REG_RSP;
            bp_register = UC_X86_REG_RBP;
            break;
        default:
            is.setstate(std::ios::failbit);
            return is;
        }
        break;
    default:
        is.setstate(std::ios::failbit);
        return is;
    }

    auto const cs = std::shared_ptr<csh>(new csh, cs_close);
    CS_FATAL(cs_open(
        spec.machine_architecture.first,
        spec.machine_mode.first, cs.get()));
    CS_FATAL(cs_option(*cs, CS_OPT_DETAIL, CS_OPT_ON));
    debugger.cs_ = cs;

    uc_engine* uc;
    UC_FATAL(uc_open(
        spec.machine_architecture.second,
        spec.machine_mode.second,
        &uc));
    debugger.uc_ = std::shared_ptr<uc_engine>(uc, uc_close);

    debugger.ip_register_ = ip_register;

    for (auto const& [address, data] : spec.memory_regions)
        debugger.allocate_memory(address, data);

    debugger.position(spec.entry_point);

    auto const stack_bottom = UINT32_MAX;
    auto const stack_size = 0x1000;
    debugger.allocate_memory(stack_bottom - stack_size + 1, stack_size);

    debugger.write_register(sp_register, stack_bottom);
    debugger.write_register(bp_register, stack_bottom);

    return is;
}

uint64_t debugger::read_register(int const id) const
{
    uint64_t value = 0;
    UC_FATAL(uc_reg_read(uc_.get(), id, &value));

    return value;
}
void debugger::write_register(int const id, uint64_t const value) const
{
    UC_FATAL(uc_reg_write(uc_.get(), id, &value));
}

void debugger::allocate_memory(uint64_t const address, size_t const size) const
{
    if (size == 0)
        return;

    size_t constexpr PAGE_SIZE = 0x1000;

    UC_FATAL(uc_mem_map(uc_.get(), address, PAGE_SIZE * ((size - 1) / PAGE_SIZE + 1), UC_PROT_ALL));
}
void debugger::allocate_memory(uint64_t const address, std::vector<uint8_t> const& data) const
{
    allocate_memory(address, data.size());
    write_memory(address, data);
}

void debugger::read_memory(uint64_t const address, std::vector<uint8_t>& data) const
{
    UC_FATAL(uc_mem_read(uc_.get(), address, &data.front(), data.size()));
}
void debugger::write_memory(uint64_t const address, std::vector<uint8_t> const& data) const
{
    if (data.empty())
        return;

    UC_FATAL(uc_mem_write(uc_.get(), address, &data.front(), data.size()));
}

std::set<uc_mem_region> debugger::get_memory_regions() const
{
    uc_mem_region* uc_memory_regions;
    uint32_t count;
    UC_FATAL(uc_mem_regions(uc_.get(), &uc_memory_regions, &count));

    std::set<uc_mem_region> const memory_regions(
        uc_memory_regions,
        uc_memory_regions + count); // NOLINT

    UC_FATAL(uc_free(uc_memory_regions));

    return memory_regions;
}

cs_err debugger::get_cs_error() const
{
    return cs_errno(*cs_);
}
uc_err debugger::get_uc_error() const
{
    return uc_errno(uc_.get());
}
