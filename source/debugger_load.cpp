#include <climits>
#include <fstream>

#include "../include/scout/debugger.h"

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

debugger debugger::load(std::string const& file_name)
{
    std::ifstream file_stream(file_name, std::ios::binary);

    if (!file_stream)
        throw std::runtime_error("Invalid file");

    return load(file_stream);
}
debugger debugger::load(std::istream& is)
{
    auto const magic_number = extract<uint32_t>(is);
    is.seekg(-sizeof(uint32_t), std::ios::cur);

    if ((magic_number & 0xFFFFu) == 0x5A4D)
        return load_pe(is);

    if (magic_number == 0x7F454C46)
        return load_elf(is);

    throw std::runtime_error("Unknown binary format");
}

debugger debugger::load_pe(std::istream& is)
{
    executable_specification specification;

    is.seekg(0x3C, std::ios::cur);
    is.seekg(extract<uint32_t>(is));

    is.seekg(0x4, std::ios::cur);

    auto const machine = extract<uint16_t>(is);

    switch (machine)
    {
    case 0x14C:
    case 0x8664:
        specification.machine_architecture = std::make_pair(CS_ARCH_X86, UC_ARCH_X86);
        break;
    default:
        throw std::runtime_error("Unknown architecture");
    }

    switch (machine)
    {
    case 0x14C:
        specification.machine_mode = std::make_pair(CS_MODE_32, UC_MODE_32);
        break;
    case 0x8664:
        specification.machine_mode = std::make_pair(CS_MODE_64, UC_MODE_64);
        break;
    default:
        throw std::runtime_error("Unknown architecture");
    }

    auto const n_sections = extract<uint16_t>(is);

    is.seekg(0xC, std::ios::cur);

    auto const optional_header_size = extract<uint16_t>(is);

    is.seekg(0x12, std::ios::cur);

    auto const relative_entry_point = extract<uint32_t>(is);

    is.seekg(0x4, std::ios::cur);

    auto image_base = extract<uint64_t>(is);

    switch (optional_header_size)
    {
    case 0xE0:
        image_base >>= sizeof(uint32_t) * CHAR_BIT;
        is.seekg(0xC0, std::ios::cur);
        break;
    case 0xF0:
        is.seekg(0xD0, std::ios::cur);
        break;
    }

    specification.entry_point = image_base + relative_entry_point;

    size_t const position = is.tellg();
    for (uint16_t section_index = 0; section_index < n_sections; ++section_index)
    {
        is.seekg(position + section_index * 0x28 + 0xC);

        auto const virtual_address = extract<uint32_t>(is);
        auto const raw_size = extract<uint32_t>(is);
        auto const raw_position = extract<uint32_t>(is);

        is.seekg(raw_position);

        specification.memory_regions.emplace(image_base + virtual_address, extract(is, raw_size));
    }

    return debugger(specification);
}
debugger debugger::load_elf(std::istream& is)
{
    // TODO: ELF support
    throw std::runtime_error("Unknown binary format");
}
