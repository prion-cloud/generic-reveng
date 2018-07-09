#include "stdafx.h"

#include "control_flow.h"
#include "data_flow.h"
#include "disassembly.h"
#include "rule_set.h"

static std::vector<std::pair<uint64_t, uint64_t>> addresses
{
    { 0x7FF7E4E2DD4C, 0x7FF7E4FF67A0 },
    { 0x7FF7E4E2EBDA, 0x7FF7E4E7CAC0 },
    { 0x7FF7E4E43F63, 0x7FF7E4F5DC10 },
    { 0x7FF7E4E50722, 0x7FF7E50AD001 },
    { 0x7FF7E4E79064, 0x7FF7E4F5E830 },
    { 0x7FF7E4F3EEB9, 0x7FF7E4EBC500 },
    { 0x7FF7E4F4438A, 0x7FF7E4F09DA7 },
    { 0x7FF7E4F58D0E, 0x7FF7E4F3C969 },
    { 0x7FF7E4F7F9BF, 0x7FF7E4F44C97 },
    { 0x7FF7E4FA8225, 0x7FF7E4E2DEF8 },
    { 0x7FF7E4FE3F3A, 0x7FF7E4EB9C72 },
    { 0x7FF7E5002462, 0x7FF7E4FF6182 },
    { 0x7FF7E5006F17, 0x7FF7E4E83659 },
    { 0x7FF7E5021D8C, 0x7FF7E4E89D84 },
    { 0x7FF7E502A93A, 0x7FF7E4EF33C4 },
    { 0x7FF7E50AF887, 0x7FF7E4EEBE4E },
    { 0x7FF7E50FFB14, 0x7FF7E50FC3AC },
    { 0x7FF7E50FFE8B, 0x7FF7E4FF73E4 }
};

static std::vector<uint8_t> load(const std::string& file_name)
{
    std::cout << "File: \"" << file_name << "\"" << std::endl;

    std::ifstream file_stream(file_name, std::ios::binary);

    if (!file_stream.is_open())
        return { };

    file_stream.seekg(0, std::ios::end);
    std::vector<uint8_t> code(file_stream.tellg());

    file_stream.seekg(0, std::ios::beg);

    file_stream.read(reinterpret_cast<char*>(&code.at(0)), code.size());

    std::cout << "Size: " << code.size() << " bytes" << std::endl;

    return code;
}

int main(const int argc, char* argv[])
{
    dsp::h_console = GetStdHandle(STD_OUTPUT_HANDLE);

    if (argc != 2)
    {
        std::cerr << dsp::colorize(FOREGROUND_RED) << "Invalid number of arguments."
                  << dsp::decolorize << std::endl;
        return EXIT_FAILURE;
    }

    const auto code = load(argv[1]);

    if (code.empty())
    {
        std::cerr << dsp::colorize(FOREGROUND_RED) << "Could not open file."
                  << dsp::decolorize << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << std::endl;

/* ---------------------------------------------------------------- */

    const disassembly disassembly(code);

    std::vector<instruction_sequence> pool;
    for (const auto [start, stop] : addresses)
    {
        const control_flow control_flow(disassembly, start, stop);
        control_flow.draw();

        const auto blocks = control_flow.get_blocks();
        pool.insert(pool.end(), blocks.begin(), blocks.end());
    }

    std::map<instruction_sequence, unsigned> power_pool;
    for (const auto& seq : pool)
    {
        for (const auto& subseq : seq.power())
            ++power_pool[subseq];
    }

    std::map<data_flow, std::vector<instruction_sequence>> flow_map;
    for (const auto& [seq, count] : power_pool)
    {
        const data_flow data_flow(seq);
        if (!data_flow->empty())
            flow_map[data_flow].push_back(seq);
    }

    rule_set rule_set;
    for (const auto& [data_flow, seqs] : flow_map)
    {
        for (const auto& seq : seqs)
        {
            // TODO: MAGIC
        }
    }

    auto stream = std::wofstream("pattern_database.json");
    rule_set.json_serialize(stream);

/* ---------------------------------------------------------------- */

    std::cout << std::endl << "COMPLETE" << std::endl;
    std::cin.get();

    return EXIT_SUCCESS;
}
