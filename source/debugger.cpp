#include "../include/follower/debugger.h"
#include "../include/follower/win_structs.h"

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

debugger::debugger(architecture const architecture, mode const mode)
{
    cs_open(to_cs(architecture), to_cs(mode), &cs_);
    cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON);

    uc_engine* uc;
    uc_open(to_uc(architecture), to_uc(mode), &uc);

    uc_ = std::shared_ptr<uc_engine>(uc, uc_close);
}
debugger::~debugger()
{
    cs_close(&cs_);
}

uint64_t debugger::position() const
{
    return read_register(UC_X86_REG_RIP);
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
    write_register(/*TODO--->*/UC_X86_REG_RIP/*<---*/, address);

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

std::istream& operator>>(std::istream& is, debugger const& debugger)
{
    // TODO: Specify file format (not only PE)

    auto const dos_header = extract<image_dos_header>(is);

    if (dos_header.e_magic != 0x5a4d)
    {
        is.setstate(std::ios::failbit);
        return is;
    }

    is.seekg(dos_header.e_lfanew);

    if (extract<uint32_t>(is) != 0x4550)
    {
        is.setstate(std::ios::failbit);
        return is;
    }

    auto const file_header = extract<image_file_header>(is);

    uint64_t entry_point;
    uint64_t image_base;
    switch (file_header.size_of_optional_header)
    {
    case sizeof(image_optional_header_32):
        {
            auto const optional_header = extract<image_optional_header_32>(is);
            entry_point = optional_header.address_of_entry_point;
            image_base = optional_header.image_base;
        }
        break;
    case sizeof(image_optional_header_64):
        {
            auto const optional_header = extract<image_optional_header_64>(is);
            entry_point = optional_header.address_of_entry_point;
            image_base = optional_header.image_base;
        }
        break;
    default:
        is.setstate(std::ios::failbit);
        return is;
    }

    std::vector<image_section_header> section_headers;
    for (unsigned i = 0; i < file_header.number_of_sections; ++i)
        section_headers.push_back(extract<image_section_header>(is));

    for (auto const& section_header : section_headers)
    {
        is.seekg(section_header.pointer_to_raw_data);

        debugger.allocate_memory(
            image_base + section_header.virtual_address,
            extract(is, section_header.size_of_raw_data));
    }

    debugger.jump(entry_point + image_base);

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
