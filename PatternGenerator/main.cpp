#include "stdafx.h"

#include "control_flow.h"
#include "data_flow.h"
#include "disassembly.h"
#include "rule_set.h"

static std::vector<std::pair<uint64_t, uint64_t>> addresses
{
    { 0x7FF7E4E2DD4C, 0x7FF7E4FF67A0 },
    //{ 0x7FF7E4E2EBDA, 0x7FF7E4E7CAC0 },
    //{ 0x7FF7E4E43F63, 0x7FF7E4F5DC10 },
    //{ 0x7FF7E4E50722, 0x7FF7E50AD001 },
    //{ 0x7FF7E4E79064, 0x7FF7E4F5E830 },
    //{ 0x7FF7E4F3EEB9, 0x7FF7E4EBC500 },
    //{ 0x7FF7E4F4438A, 0x7FF7E4F09DA7 },
    //{ 0x7FF7E4F58D0E, 0x7FF7E4F3C969 },
    //{ 0x7FF7E4F7F9BF, 0x7FF7E4F44C97 },
    //{ 0x7FF7E4FA8225, 0x7FF7E4E2DEF8 },
    //{ 0x7FF7E4FE3F3A, 0x7FF7E4EB9C72 },
    //{ 0x7FF7E5002462, 0x7FF7E4FF6182 },
    //{ 0x7FF7E5006F17, 0x7FF7E4E83659 },
    //{ 0x7FF7E5021D8C, 0x7FF7E4E89D84 },
    //{ 0x7FF7E502A93A, 0x7FF7E4EF33C4 },
    //{ 0x7FF7E50AF887, 0x7FF7E4EEBE4E },
    //{ 0x7FF7E50FFB14, 0x7FF7E50FC3AC },
    //{ 0x7FF7E50FFE8B, 0x7FF7E4FF73E4 }
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

    //std::vector<uint64_t> adds
    //{
    //    0x7FF7E4E33F45,
    //    0x7FF7E4E33F49,
    //    0x7FF7E4E33F4B,
    //    0x7FF7E4E33F4E,
    //    0x7FF7E4E33F52,
    //    0x7FF7E4F0BB08,
    //    0x7FF7E4F0BB0B,
    //    0x7FF7E5066145,
    //    0x7FF7E5066147,
    //    0x7FF7E500546B,
    //    0x7FF7E500546F,
    //    0x7FF7E5005473,
    //    0x7FF7E5005478,
    //    0x7FF7E44E0E06,
    //    0x7FF7E44E0E0B
    //};
    //const disassembly disassembly(code);
    //data_flow data_flow;
    //for (const auto a : adds)
    //{
    //    const auto instruction = disassembly[a];
    //    std::cout << instruction.to_string(true) << std::endl;
    //    data_flow.apply(instruction);
    //    for (const auto& string : data_flow.to_string())
    //        std::cout << "\t" << string << std::endl;
    //}
    //auto instruction = disassembly[0x7FF7E4E708BC];
    //for (auto i = 0; i < 23; ++i)
    //{
    //    std::cout << instruction.to_string(true) << std::endl;
    //    data_flow.apply(instruction);
    //    for (const auto& string : data_flow.to_string())
    //        std::cout << "\t" << string << std::endl;
    //    instruction = disassembly[data_flow.inspect_rip().front()];
    //}

    const disassembly disassembly(code);

    std::vector<instruction_sequence> pool;
    for (const auto [start, stop] : addresses)
    {
        const control_flow control_flow(disassembly, start, stop);
        //std::cout << control_flow.to_string() << std::endl << std::endl;

        const auto blocks = control_flow.get_blocks();
        std::cout << "CFG: " << std::hex << std::uppercase << start << " (" << std::dec << blocks.size() << ")" << std::endl;

        pool.insert(pool.end(), blocks.begin(), blocks.begin() + 10);
    }
    
    std::map<unsigned, std::map<instruction_sequence_representation, std::vector<instruction_sequence>>> reduced_pool;
    {
        std::map<instruction_sequence_representation, std::vector<instruction_sequence>> power_pool;
        for (const auto& seq : pool)
        {
            for (const auto& subseq : seq.power())
            {
                std::map<x86_reg, std::wstring> reg_map;
                std::map<int64_t, std::wstring> num_map;
                power_pool[subseq.get_representation(reg_map, num_map)].push_back(subseq);
            }
        }

        for (const auto& [rep, seqs] : power_pool)
        {
            if (seqs.size() > 1)
                reduced_pool[rep.value.size()].emplace(rep, seqs);
        }
    }

    rule_set rule_set;
    auto did = false;
    for (auto rit = reduced_pool.rbegin(); rit != reduced_pool.rend(); ++rit)
    {
        for (const auto& [rep, seqs] : rit->second)
        {
            std::optional<std::vector<std::wstring>> replacement = std::nullopt;
            for (const auto& seq : seqs)
            {
                const data_flow data_flow(seq);
                if (data_flow.size() > seq->size())
                    continue;

                //for (unsigned i = 0; i < seq->size(); ++i)
                //    std::cout << seq->at(i).to_string(true) << std::endl;
                //for (const auto& s : data_flow.to_string())
                //    std::cout << "\t" << s << std::endl;

                replacement = data_flow.get_replacement();
            }

            if (!replacement.has_value())
                continue;

            auto pattern = rep.value; // TODO

            rule_set.add(pattern, *replacement);

            did = true;
            break;
        }

        if (did)
            break;
    }

    auto stream = std::wofstream("pattern_database.json");
    rule_set.json_serialize(stream);

    std::cout << std::endl << "COMPLETE" << std::endl;
    std::cin.get();

    return EXIT_SUCCESS;
}
