#include "../include/follower/loader.h"

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

void load_pe(std::istream& is, load_data* data)
{
    is.seekg(0x3C);
    is.seekg(extract<uint32_t>(is));

    if (extract<uint32_t>(is) != 0x4550)
    {
        is.setstate(std::ios::failbit);
        return;
    }

    auto const machine = extract<uint16_t>(is);

    switch (machine)
    {
    case 0x1C0:
        data->machine_architecture = std::make_pair(CS_ARCH_ARM, UC_ARCH_ARM);
        break;
    case 0xAA64:
        data->machine_architecture = std::make_pair(CS_ARCH_ARM64, UC_ARCH_ARM64);
        break;
    case 0x162:
    case 0x266:
    case 0x366:
    case 0x466:
        data->machine_architecture = std::make_pair(CS_ARCH_MIPS, UC_ARCH_MIPS);
        break;
    case 0x14C:
    case 0x8664:
        data->machine_architecture = std::make_pair(CS_ARCH_X86, UC_ARCH_X86);
        break;
    default:
        is.setstate(std::ios::failbit);
        return;
    }

    switch (machine)
    {
    case 0x266:
    case 0x466:
        data->machine_mode = std::make_pair(CS_MODE_16, UC_MODE_16);
        break;
    case 0x14C:
    case 0x162:
    case 0x1C0:
    case 0x366:
        data->machine_mode = std::make_pair(CS_MODE_32, UC_MODE_32);
        break;
    case 0x8664:
    case 0xAA64:
        data->machine_mode = std::make_pair(CS_MODE_64, UC_MODE_64);
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

    data->entry_point = image_base + entry_point;

    size_t const position = is.tellg();
    for (uint16_t section_index = 0; section_index < n_sections; ++section_index)
    {
        is.seekg(position + section_index * 0x28 + 0xC);

        auto const virtual_address = extract<uint32_t>(is);
        auto const raw_size = extract<uint32_t>(is);
        auto const raw_position = extract<uint32_t>(is);

        is.seekg(raw_position);

        data->memory_regions.emplace(image_base + virtual_address, extract(is, raw_size));
    }
}

void load_elf(std::istream& is, load_data* data)
{
    // TODO: ELF support
    is.setstate(std::ios::failbit);
}

load_data load(std::istream& is)
{
    load_data data;

    auto const magic_number = extract<uint32_t>(is);

    if ((magic_number & 0xFFFFu) == 0x5A4D)
    {
        load_pe(is, &data);
        return data;
    }

    if (magic_number == 0x7F454C46)
    {
        load_elf(is, &data);
        return data;
    }

    is.setstate(std::ios::failbit);
    return data;
}
