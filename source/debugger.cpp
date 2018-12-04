#include <scout/debugger.hpp>

bool operator<(uc_mem_region const& a, uc_mem_region const& b)
{
    return a.end < b.begin;
}

void handle_cs_error(cs_err const error_code)
{
    if (error_code != CS_ERR_OK)
        throw std::runtime_error(cs_strerror(error_code));
}
void handle_uc_error(uc_err const error_code)
{
    if (error_code != UC_ERR_OK)
        throw std::runtime_error(uc_strerror(error_code));
}

uint64_t debugger::position() const
{
    return read_register(ip_register_);
}
bool debugger::position(uint64_t const address)
{
    write_register(ip_register_, address);

    return is_mapped();
}

machine_instruction debugger::current_instruction() const
{
    auto const address = position();

    auto const code_vector = read_memory(address, machine_instruction::SIZE);

    std::array<uint8_t, machine_instruction::SIZE> code_array;
    std::move(code_vector.cbegin(), code_vector.cend(), code_array.begin());

    return machine_instruction(cs_, address, code_array);
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

bool debugger::skip()
{
    return skip(current_instruction().disassemble()->size);
}
bool debugger::skip(uint64_t const count)
{
    return position(position() + count);
}

bool debugger::step_into()
{
    return uc_emu_start(uc_.get(), position(), 0, 0, 1) == UC_ERR_OK;
}

debugger::debugger(executable_specification const& specification)
{
    int sp_register;
    int bp_register;

    switch (specification.machine_architecture.second)
    {
    case UC_ARCH_X86:
        switch (specification.machine_mode.second)
        {
        case UC_MODE_16:
            ip_register_ = UC_X86_REG_IP;
            sp_register = UC_X86_REG_SP;
            bp_register = UC_X86_REG_BP;
            break;
        case UC_MODE_32:
            ip_register_ = UC_X86_REG_EIP;
            sp_register = UC_X86_REG_ESP;
            bp_register = UC_X86_REG_EBP;
            break;
        case UC_MODE_64:
            ip_register_ = UC_X86_REG_RIP;
            sp_register = UC_X86_REG_RSP;
            bp_register = UC_X86_REG_RBP;
            break;
        default:
            throw std::runtime_error("Unsupported architecture");
        }
        break;
    default:
        throw std::runtime_error("Unsupported architecture");
    }

    cs_ = std::shared_ptr<csh>(new csh, cs_close);
    handle_cs_error(
        cs_open(
            specification.machine_architecture.first,
            specification.machine_mode.first,
            cs_.get()));
    handle_cs_error(cs_option(*cs_, CS_OPT_DETAIL, CS_OPT_ON));

    uc_engine* uc;
    handle_uc_error(
        uc_open(
            specification.machine_architecture.second,
            specification.machine_mode.second,
            &uc));
    uc_ = std::shared_ptr<uc_engine>(uc, uc_close);

    for (auto const& [address, data] : specification.memory_regions)
        allocate_memory(address, data);

    position(specification.entry_point);

    auto const stack_bottom = UINT32_MAX;
    auto const stack_size = 0x1000;
    allocate_memory(stack_bottom - stack_size + 1, stack_size);

    write_register(sp_register, stack_bottom);
    write_register(bp_register, stack_bottom);
}

uint64_t debugger::read_register(int const id) const
{
    uint64_t value = 0;
    handle_uc_error(uc_reg_read(uc_.get(), id, &value));

    return value;
}
void debugger::write_register(int const id, uint64_t const value)
{
    handle_uc_error(uc_reg_write(uc_.get(), id, &value));
}

void debugger::allocate_memory(uint64_t const address, size_t const size)
{
    if (size == 0)
        return;

    size_t constexpr PAGE_SIZE = 0x1000;

    handle_uc_error(
        uc_mem_map(uc_.get(), address, PAGE_SIZE * ((size - 1) / PAGE_SIZE + 1), UC_PROT_ALL));
}
void debugger::allocate_memory(uint64_t const address, std::vector<uint8_t> const& data)
{
    allocate_memory(address, data.size());
    write_memory(address, data);
}

std::vector<uint8_t> debugger::read_memory(uint64_t const address, size_t const size) const
{
    std::vector<uint8_t> data(size);
    handle_uc_error(uc_mem_read(uc_.get(), address, &data.front(), data.size()));

    return data;
}
void debugger::write_memory(uint64_t const address, std::vector<uint8_t> const& data)
{
    if (data.empty())
        return;

    handle_uc_error(uc_mem_write(uc_.get(), address, &data.front(), data.size()));
}

std::set<uc_mem_region> debugger::get_memory_regions() const
{
    uc_mem_region* uc_memory_regions;
    uint32_t count;
    handle_uc_error(uc_mem_regions(uc_.get(), &uc_memory_regions, &count));

    std::set<uc_mem_region> const memory_regions(
        uc_memory_regions,
        uc_memory_regions + count); // NOLINT

    handle_uc_error(uc_free(uc_memory_regions));

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
