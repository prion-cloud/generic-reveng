#include <climits>
#include <regex>

#include "loader.hpp"

loader::loader(disassembler* const disassembler, emulator* const emulator)
    : disassembler_(disassembler), emulator_(emulator) { }

void loader::operator()(std::vector<uint8_t> const& data) const
{
    if (std::memcmp(data.data(), "MZ", 2) == 0)
    {
        load_pe(data);
        return;
    }

    // TODO

    throw std::runtime_error("Unknown binary format");
}

std::vector<uint64_t> regex_examine_data(std::vector<uint8_t> const& data, std::string const& regex_pattern,
    size_t data_offset = 0)
{
    // NOLINTNEXTLINE [cppcoreguidelines-pro-type-reinterpret-cast]
    std::string_view const data_str(reinterpret_cast<char const*>(data.data()), data.size());

    std::cmatch results;
    std::regex_search(data_str.begin() + data_offset, data_str.end(), results, std::regex(regex_pattern));

    std::vector<uint64_t> values(results.size() - 1);
    std::transform(results.begin() + 1, results.end(), values.begin(),
        [](auto const& match)
        {
            std::vector<uint8_t> bytes(match.first, match.second);
            bytes.resize(sizeof(uint64_t));

            return *reinterpret_cast<uint64_t const*>(bytes.data()); // NOLINT [cppcoreguidelines-pro-type-reinterpret-cast]
        });

    return values;
}

void loader::load_pe(std::vector<uint8_t> const& data) const
{
    auto constexpr dos_info_pattern = "MZ[^]{58}([^]{4})";
    auto constexpr pe_info_pattern = "PE\\0\\0([^]{2})([^]{2})[^]{12}([^]{2})[^]{18}([^]{4})[^]{4}([^]{8})";
    auto constexpr pe_section_info_pattern = "([^]{4})([^]{4})([^]{4})";

    auto const dos_info = ::regex_examine_data(data, dos_info_pattern);
    auto const pe_info = ::regex_examine_data(data, pe_info_pattern, dos_info.at(0));

    std::pair<disassembler::architecture, emulator::architecture> architecture;
    std::pair<disassembler::mode, emulator::mode> mode;
    int ip_register;
    switch (pe_info.at(0))
    {
    case 0x14C:
        architecture = std::make_pair(CS_ARCH_X86, UC_ARCH_X86);
        mode = std::make_pair(CS_MODE_32, UC_MODE_32);
        ip_register = UC_X86_REG_EIP;
        break;
    case 0x8664:
        architecture = std::make_pair(CS_ARCH_X86, UC_ARCH_X86);
        mode = std::make_pair(CS_MODE_64, UC_MODE_64);
        ip_register = UC_X86_REG_RIP;
        break;
    default:
        throw std::runtime_error("Unknown architecture");
    }

    *disassembler_ = disassembler(architecture.first, mode.first);
    *emulator_ = emulator(architecture.second, mode.second, ip_register);

    uint64_t image_base = pe_info.at(4);
    if (pe_info.at(2) == 0xE0)
        image_base >>= sizeof(uint32_t) * CHAR_BIT;

    emulator_->position(image_base + pe_info.at(3));

    for (size_t section_index = 0; section_index < pe_info.at(1); ++section_index)
    {
        auto const section_info = ::regex_examine_data(data, pe_section_info_pattern,
            section_index * 0x28 + dos_info.at(0) + pe_info.at(2) + 0x24);

        if (section_info.at(1) == 0)
            continue;

        auto const data_begin = data.begin() + section_info.at(2);
        emulator_->allocate_memory(image_base + section_info.at(0),
            std::vector<uint8_t>(data_begin, data_begin + section_info.at(1)));
    }
}
