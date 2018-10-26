#include "../include/follower/debugger.h"

template <typename T>
T extract(std::istream& is)
{
    T result { };
    is.read(reinterpret_cast<char*>(&result), sizeof(T));

    return result;
}
std::vector<uint8_t> extract(std::istream& is, size_t size)
{
    std::vector<uint8_t> result(size);
    is.read(reinterpret_cast<char*>(&result.front()), size);

    return result;
}

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
    auto const magic_number = extract<uint32_t>(is);

    if ((magic_number & 0xFFFFu) == 0x5A4D)
        debugger.load_pe(is);
    else if (magic_number == 0x7F454C46)
        debugger.load_elf(is);
    else is.setstate(std::ios::failbit);

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

void debugger::load_pe(std::istream& is)
{
    is.seekg(0x3C);
    is.seekg(extract<uint32_t>(is));

    if (extract<uint32_t>(is) != 0x4550)
    {
        is.setstate(std::ios::failbit);
        return;
    }

    auto const machine = extract<uint16_t>(is);

    std::pair<cs_arch, uc_arch> architecture;
    std::pair<cs_mode, uc_mode> mode;

    switch (machine)
    {
    case 0x1C0:
        architecture = std::make_pair(CS_ARCH_ARM, UC_ARCH_ARM);
        break;
    case 0xAA64:
        architecture = std::make_pair(CS_ARCH_ARM64, UC_ARCH_ARM64);
        break;
    case 0x162:
    case 0x266:
    case 0x366:
    case 0x466:
        architecture = std::make_pair(CS_ARCH_MIPS, UC_ARCH_MIPS);
        break;
    case 0x14C:
    case 0x8664:
        architecture = std::make_pair(CS_ARCH_X86, UC_ARCH_X86);
        break;
    default:
        is.setstate(std::ios::failbit);
        return;
    }

    switch (machine)
    {
    case 0x266:
    case 0x466:
        mode = std::make_pair(CS_MODE_16, UC_MODE_16);
        break;
    case 0x14C:
    case 0x162:
    case 0x1C0:
    case 0x366:
        mode = std::make_pair(CS_MODE_32, UC_MODE_32);
        break;
    case 0x8664:
    case 0xAA64:
        mode = std::make_pair(CS_MODE_64, UC_MODE_64);
        break;
    default:
        is.setstate(std::ios::failbit);
        return;
    }

    auto const n_sections = extract<uint16_t>(is);

    is.seekg(0xC, std::ios::cur);

    auto const optional_header_size = extract<uint16_t>(is);

    is.seekg(0x12, std::ios::cur);

    auto const entry_point = extract<uint32_t>(is);

    is.seekg(0x4, std::ios::cur);

    auto image_base = extract<uint64_t>(is);

    switch (optional_header_size)
    {
    case 0xE0:
        image_base &= 0xFFFF;
        is.seekg(0xC0, std::ios::cur);
        break;
    case 0xF0:
        is.seekg(0xD0, std::ios::cur);
        break;
    default:
        is.setstate(std::ios::failbit);
        return;
    }

    cs_open(architecture.first, mode.first, &cs_);
    cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON);

    uc_engine* uc;
    uc_open(architecture.second, mode.second, &uc);

    uc_ = std::shared_ptr<uc_engine>(uc, uc_close);

    int stack_pointer_id;
    int base_pointer_id;

    switch (architecture.second)
    {
    case UC_ARCH_X86:
        switch (mode.second)
        {
        case UC_MODE_16:
            instruction_pointer_id_ = UC_X86_REG_IP;
            stack_pointer_id = UC_X86_REG_SP;
            base_pointer_id = UC_X86_REG_BP;
            break;
        case UC_MODE_32:
            instruction_pointer_id_ = UC_X86_REG_EIP;
            stack_pointer_id = UC_X86_REG_ESP;
            base_pointer_id = UC_X86_REG_EBP;
            break;
        case UC_MODE_64:
            instruction_pointer_id_ = UC_X86_REG_RIP;
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

    size_t const position = is.tellg();
    for (uint16_t section_index = 0; section_index < n_sections; ++section_index)
    {
        is.seekg(position + section_index * 0x28 + 0xC);

        auto const virtual_address = extract<uint32_t>(is);
        auto const raw_size = extract<uint32_t>(is);
        auto const raw_position = extract<uint32_t>(is);

        is.seekg(raw_position);

        allocate_memory(image_base + virtual_address, extract(is, raw_size));
    }

    jump(image_base + entry_point);

    auto const stack_bottom = UINT32_MAX;
    auto const stack_size = 0x1000;
    allocate_memory(stack_bottom - stack_size + 1, stack_size);

    write_register(stack_pointer_id, stack_bottom);
    write_register(base_pointer_id, stack_bottom);
}

void debugger::load_elf(std::istream& is)
{
    // TODO: ELF support
    is.setstate(std::ios::failbit);
}
