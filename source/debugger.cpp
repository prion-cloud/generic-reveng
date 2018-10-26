#include "../include/follower/debugger.h"
#include "../include/follower/loader.h"

bool operator<(const uc_mem_region a, const uc_mem_region b)
{
    return a.end <= b.begin;
}

debugger::~debugger()
{
    cs_close(&cs_);
}

uint64_t debugger::position() const
{
    return read_register(instruction_pointer_id_);
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

bool debugger::jump(uint64_t const address) const
{
    write_register(instruction_pointer_id_, address);

    return is_mapped();
}

bool debugger::skip() const
{
    return skip(disassemble().code.size());
}
bool debugger::skip(uint64_t const count) const
{
    return jump(position() + count);
}

bool debugger::step_into() const
{
    return uc_emu_start(uc_.get(), position(), 0, 0, 1) == UC_ERR_OK;
}

instruction debugger::disassemble() const
{
    return disassemble_range(1).front();
}
instruction debugger::disassemble(uint64_t const address) const
{
    return disassemble_range(address, 1).front();
}

std::vector<instruction> debugger::disassemble_range(size_t const count) const
{
    return disassemble_range(position(), count);
}
std::vector<instruction> debugger::disassemble_range(uint64_t const address, size_t const count) const
{
    std::vector<uint8_t> data_buffer(0x10);
    read_memory(address, data_buffer);

    cs_insn* cs_instructions;
    cs_disasm(cs_, &data_buffer.front(), data_buffer.size(), address, count, &cs_instructions);

    std::vector<instruction> const instructions(
        cs_instructions,
        cs_instructions + count); // NOLINT

    cs_free(cs_instructions, count);

    return instructions;
}

std::istream& operator>>(std::istream& is, debugger& debugger)
{
    auto const load_data = load(is);

    if (is.fail())
        return is;

    cs_open(
        load_data.machine_architecture.first,
        load_data.machine_mode.first, &debugger.cs_);
    cs_option(debugger.cs_, CS_OPT_DETAIL, CS_OPT_ON);

    uc_engine* uc;
    uc_open(
        load_data.machine_architecture.second,
        load_data.machine_mode.second,
        &uc);

    debugger.uc_ = std::shared_ptr<uc_engine>(uc, uc_close);

    int stack_pointer_id;
    int base_pointer_id;

    switch (load_data.machine_architecture.second)
    {
    case UC_ARCH_X86:
        switch (load_data.machine_mode.second)
        {
        case UC_MODE_16:
            debugger.instruction_pointer_id_ = UC_X86_REG_IP;
            stack_pointer_id = UC_X86_REG_SP;
            base_pointer_id = UC_X86_REG_BP;
            break;
        case UC_MODE_32:
            debugger.instruction_pointer_id_ = UC_X86_REG_EIP;
            stack_pointer_id = UC_X86_REG_ESP;
            base_pointer_id = UC_X86_REG_EBP;
            break;
        case UC_MODE_64:
            debugger.instruction_pointer_id_ = UC_X86_REG_RIP;
            stack_pointer_id = UC_X86_REG_RSP;
            base_pointer_id = UC_X86_REG_RBP;
            break;
        default:
            throw std::invalid_argument("Unsupported machine mode");
        }
        break;
    default:
        throw std::invalid_argument("Unsupported machine architecture");
    }

    for (auto const& [address, data] : load_data.memory_regions)
        debugger.allocate_memory(address, data);

    debugger.jump(load_data.entry_point);

    auto const stack_bottom = UINT32_MAX;
    auto const stack_size = 0x1000;
    debugger.allocate_memory(stack_bottom - stack_size + 1, stack_size);

    debugger.write_register(stack_pointer_id, stack_bottom);
    debugger.write_register(base_pointer_id, stack_bottom);

    return is;
}

uint64_t debugger::read_register(int const id) const
{
    uint64_t value = 0;
    uc_reg_read(uc_.get(), id, &value);

    return value;
}
void debugger::write_register(int const id, uint64_t const value) const
{
    uc_reg_write(uc_.get(), id, &value);
}

void debugger::allocate_memory(uint64_t const address, size_t const size) const
{
    size_t constexpr PAGE_SIZE = 0x1000;

    uc_mem_map(uc_.get(), address, PAGE_SIZE * ((size - 1) / PAGE_SIZE + 1), UC_PROT_ALL);
}
void debugger::allocate_memory(uint64_t const address, std::vector<uint8_t> const& data) const
{
    allocate_memory(address, data.size());
    write_memory(address, data);
}

void debugger::read_memory(uint64_t const address, std::vector<uint8_t>& data) const
{
    uc_mem_read(uc_.get(), address, &data.front(), data.size());
}
void debugger::write_memory(uint64_t const address, std::vector<uint8_t> const& data) const
{
    uc_mem_write(uc_.get(), address, &data.front(), data.size());
}

std::set<uc_mem_region> debugger::get_memory_regions() const
{
    uc_mem_region* uc_memory_regions;
    uint32_t count;
    uc_mem_regions(uc_.get(), &uc_memory_regions, &count);

    std::set<uc_mem_region> const memory_regions(
        uc_memory_regions,
        uc_memory_regions + count); // NOLINT

    uc_free(uc_memory_regions);

    return memory_regions;
}
