#include "stdafx.h"

#include "console.h"
#include "control_flow_graph.h"

#define FILE_1 "text1.dis"
#define FILE_2 "text2.dis"

static std::vector<uint64_t> addresses =
{

    // (82) Successful
    0x7FF7E4C59000,
    0x7FF7E4E2DD4C,
    0x7FF7E4E2EBDA,
    0x7FF7E4E384DA,
    0x7FF7E4E3FDE6,
    0x7FF7E4E4175A,
    0x7FF7E4E432F8,
    0x7FF7E4E43F63,
    0x7FF7E4E50722,
    0x7FF7E4E51588,
    0x7FF7E4E52291,
    0x7FF7E4E6C311,
    0x7FF7E4E6DFEB,
    0x7FF7E4E7140D,
    0x7FF7E4E79064,
    0x7FF7E4E7A7E3,
    0x7FF7E4E7B544,
    0x7FF7E4E81252,
    0x7FF7E4E83FE1,
    0x7FF7E4E88A77,
    0x7FF7E4E8BD57,
    0x7FF7E4E90189,
    0x7FF7E4E92750,
    0x7FF7E4EABFBA,
    0x7FF7E4EB061B,
    0x7FF7E4EB2228,
    0x7FF7E4EE75A5,
    0x7FF7E4F08493,
    0x7FF7E4F2EBC3,
    0x7FF7E4F2F773,
    0x7FF7E4F3EEB9,
    0x7FF7E4F4438A,
    0x7FF7E4F4443A,
    0x7FF7E4F46D6B,
    0x7FF7E4F58D0E,
    0x7FF7E4F59D44,
    0x7FF7E4F64311,
    0x7FF7E4F7481E,
    0x7FF7E4F7A3E2,
    0x7FF7E4F7F9BF,
    0x7FF7E4F816C5,
    0x7FF7E4F9A830,
    0x7FF7E4F9D6AE,
    0x7FF7E4FA8225,
    0x7FF7E4FB06CA,
    0x7FF7E4FB928F,
    0x7FF7E4FE3F3A,
    0x7FF7E4FE82EF,
    0x7FF7E4FEB7E0,
    0x7FF7E4FFBF79,
    0x7FF7E4FFCBF2,
    0x7FF7E5002462,
    0x7FF7E50038A4,
    0x7FF7E5003D42,
    0x7FF7E5006F17,
    0x7FF7E501009E,
    0x7FF7E5021A2F,
    0x7FF7E5021D8C,
    0x7FF7E5022E0D,
    0x7FF7E502A93A,
    0x7FF7E505BAB8,
    0x7FF7E505EDE6,
    0x7FF7E505FEC3,
    0x7FF7E50667F9,
    0x7FF7E5069E9B,
    0x7FF7E506D951,
    0x7FF7E50AADBC,
    0x7FF7E50ACC94,
    0x7FF7E50AF887,
    0x7FF7E50B9764,
    0x7FF7E50BB9A7,
    0x7FF7E50BDAF5,
    0x7FF7E50BE9EB,
    0x7FF7E50BEFF1,
    0x7FF7E50BF3DC,
    0x7FF7E50DAB37,
    0x7FF7E50DB892,
    0x7FF7E50E3B7F,
    0x7FF7E50FF016,
    0x7FF7E50FFB14,
    0x7FF7E50FFE8B,
    0x7FF7E51009E5,

/*
    // (1) BUG: Emulation error
    0x7FF7E50EA65F,
*/
/*
    // (16) BUG: Exceptions
    0x7FF7E4E30D06,
    0x7FF7E4E804FF,
    0x7FF7E4E8E482,
    0x7FF7E4E8F086,
    0x7FF7E4EAF4D8,
    0x7FF7E4EBA94C,
    0x7FF7E4F25A32,
    0x7FF7E4F32F71,
    0x7FF7E4F4A1F1,
    0x7FF7E4FAB08F,
    0x7FF7E4FE4E12,
    0x7FF7E500BD6C,
    0x7FF7E506EF56,
    0x7FF7E50B7020,
    0x7FF7E50DD4E2,
    0x7FF7E510058B,
*/
/*
    // (53) BUG: CCCCCCCC...
    0x7FF7E4E2E970,
    0x7FF7E4E2FD58,
    0x7FF7E4E367C0,
    0x7FF7E4E4435F,
    0x7FF7E4E4A879,
    0x7FF7E4E502A7,
    0x7FF7E4E6DD6A,
    0x7FF7E4E6F484,
    0x7FF7E4E7D3CA,
    0x7FF7E4E7DCBA,
    0x7FF7E4E83F12,
    0x7FF7E4E8446E,
    0x7FF7E4E8BB46,
    0x7FF7E4E9330F,
    0x7FF7E4EAD13C,
    0x7FF7E4EB2C4C,
    0x7FF7E4EB7C74,
    0x7FF7E4EEF104,
    0x7FF7E4F28FF8,
    0x7FF7E4F350E5,
    0x7FF7E4F39E5E,
    0x7FF7E4F3CEA3,
    0x7FF7E4F45F84,
    0x7FF7E4F551AD,
    0x7FF7E4F5E4C2,
    0x7FF7E4F6061E,
    0x7FF7E4F73F69,
    0x7FF7E4F74C96,
    0x7FF7E4F8279C,
    0x7FF7E4F82D3F,
    0x7FF7E4FA059D,
    0x7FF7E4FA5C4F,
    0x7FF7E4FAAE85,
    0x7FF7E4FABC00,
    0x7FF7E4FB055A,
    0x7FF7E4FBA639,
    0x7FF7E4FCEB3D,
    0x7FF7E4FE51D8,
    0x7FF7E4FE5745,
    0x7FF7E4FE6DC3,
    0x7FF7E4FF9717,
    0x7FF7E4FFD38C,
    0x7FF7E501B823,
    0x7FF7E50252C6,
    0x7FF7E5059F80,
    0x7FF7E505E8CC,
    0x7FF7E5061A71,
    0x7FF7E5064334,
    0x7FF7E50A3072,
    0x7FF7E50A69FD,
    0x7FF7E50B9F07,
    0x7FF7E50BB6AD,
    0x7FF7E50BF7A3,
*/
};

class deobfuscator_x86
{
    std::shared_ptr<debugger> debugger_;

public:

    explicit deobfuscator_x86(loader& loader, std::vector<uint8_t> code)
        : debugger_(std::make_shared<debugger>(loader, code)) { }

    std::vector<control_flow_graph_x86> inspect_framed(std::vector<uint64_t> addresses) const
    {
        std::vector<control_flow_graph_x86> cfgs;
        for (unsigned i = 0; i < addresses.size(); ++i)
        {
            const auto address = addresses.at(i);

            std::cout << std::setw(7) << std::left << "#" + std::to_string(i + 1) + ":"
                      << std::hex << std::uppercase << address << std::endl;

            cfgs.emplace_back(debugger_, address);

            std::cout << std::endl;
        }

        return cfgs;
    }
};

int main(const int argc, char* argv[])
{
    h_console = GetStdHandle(STD_OUTPUT_HANDLE);

    if (argc != 2)
    {
        std::cerr << "Invalid number of arguments." << std::endl;
        return -1;
    }

    const std::string file_name(argv[1]);

    std::cout << "File: \"" << file_name << "\"" << std::endl;

    std::ifstream file_stream(file_name, std::ios::binary);

    if (!file_stream.is_open())
    {
        std::cerr << "Could not open file." << std::endl;
        return -1;
    }

    file_stream.seekg(0, std::ios::end);
    std::vector<uint8_t> code(file_stream.tellg());

    file_stream.seekg(0, std::ios::beg);

    file_stream.read(reinterpret_cast<char*>(&code.at(0)), code.size());

    std::cout << "Size: " << code.size() << " bytes" << std::endl << std::endl;

    // -----

    try
    {
        global_flags.lazy = true;
        global_flags.ugly = true;

        loader_pe loader;

        const auto graphs = deobfuscator_x86(loader, code).inspect_framed(addresses);
    }
    catch (std::runtime_error& err)
    {
        std::cerr << colorize(FOREGROUND_RED) << err.what() << decolorize << std::endl;
        return EXIT_FAILURE;
    }

    // -----

    std::cin.get();
    return 0;
}
