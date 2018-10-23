#include "../include/follower/debugger.h"
#include "../include/follower/win_structs.h"

debugger::debugger(architecture const architecture, mode const mode)
{
    uc_engine* uc;
    uc_open(to_uc(architecture), to_uc(mode), &uc);

    uc_ = std::shared_ptr<uc_engine>(uc, uc_close);
}

uint64_t debugger::position() const
{
    return read_register(UC_X86_REG_RIP);
}

void debugger::jump(uint64_t const address) const
{
    write_register(UC_X86_REG_RIP, address);
}

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

std::istream& operator>>(std::istream& is, debugger const& debugger)
{
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
