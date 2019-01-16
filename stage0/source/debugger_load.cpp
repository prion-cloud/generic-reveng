#include <climits>
#include <fstream>
#include <numeric>
#include <regex>

#include "debugger.hpp"

std::vector<size_t> regex_search_values(std::vector<char> const& data, std::string const& regex_string, std::vector<char>::size_type offset = 0)
{
    std::match_results<std::vector<char>::const_iterator> results;
    std::regex_search(data.begin() + offset, data.end(), results, std::regex(regex_string));

    std::vector<size_t> values(results.size() - 1);
    std::transform(results.begin() + 1, results.end(), values.begin(),
        [](auto const& match)
        {
            std::vector<char> bytes(match.first, match.second);
            bytes.resize(sizeof(size_t));

            return *reinterpret_cast<size_t const*>(bytes.data());
        });

    return values;
}

std::unique_ptr<executable const> executable::load_pe(std::vector<char> const& data)
{
    auto pe_binary = std::make_unique<executable>();

    auto const dos_info =
        regex_search_values(data, "MZ.{58}(.{4})");
    auto const pe_info =
        regex_search_values(data, "PE\\0\\0(.{2})(.{2}).{12}(.{2}).{18}(.{4}).{4}(.{8})", dos_info.at(0));

    switch (pe_info.at(0))
    {
    case 0x14C:
        pe_binary->architecture = machine_architecture::x86_32;
        break;
    case 0x8664:
        pe_binary->architecture = machine_architecture::x86_64;
        break;
    default:
        throw std::runtime_error("Unknown architecture");
    }

    uint64_t image_base = pe_info.at(4);
    if (pe_info.at(2) == 0xE0)
        image_base >>= sizeof(uint32_t) * CHAR_BIT;

    pe_binary->entry_point = image_base + pe_info.at(3);

    for (size_t section_index = 0; section_index < pe_info.at(1); ++section_index)
    {
        auto const section_info =
            regex_search_values(data, "(.{4})(.{4})(.{4})", section_index * 0x28 + dos_info.at(0) + pe_info.at(2) + 0x24);

        auto const start = data.begin() + section_info.at(2);
        pe_binary->sections.emplace_back(
            image_base + section_info.at(0),
            std::vector<uint8_t>(start, start + section_info.at(1)));
    }

    return std::move(pe_binary);
}

std::unique_ptr<debugger const> debugger::load_file(std::string const& file_name)
{
    std::ifstream file_stream(file_name, std::ios::binary);

    if (!file_stream)
        throw std::runtime_error("Invalid file");

    std::vector<char> data(
        (std::istreambuf_iterator<char>(file_stream)),
        std::istreambuf_iterator<char>());

    return std::make_unique<debugger const>(*executable::load_pe(data));
}
