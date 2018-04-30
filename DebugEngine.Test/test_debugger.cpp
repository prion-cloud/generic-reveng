#include "stdafx.h"

#include "../DebugEngine.Static/debugger.h"

void test_file(const std::string file_name, const uint16_t machine, const std::vector<std::tuple<bool, bool, instruction, std::string>> expected)
{
    FILE* file;
    fopen_s(&file, file_name.c_str(), "rb");

    ASSERT_NE(nullptr, file);

    fseek(file, 0, SEEK_END);
    const auto length = ftell(file);
    rewind(file);

    const auto buffer = static_cast<char*>(malloc(length));
    fread(buffer, sizeof(char), length, file);
    fclose(file);

    const auto bytes = std::vector<uint8_t>(buffer, buffer + length);
    free(buffer);

    const auto loader = new loader_pe();
    const auto dbg = new debugger(loader, machine, bytes);

    delete loader;

    for (auto exp_ins : expected)
    {
        instruction ins;
        std::string label;
        std::map<std::string, uint64_t> registers;

        ASSERT_FALSE(dbg->debug(ins, label, registers));

        if (std::get<0>(exp_ins))
            EXPECT_EQ(std::get<2>(exp_ins).address, ins.address);

        if (std::get<1>(exp_ins))
        {
            EXPECT_EQ(std::get<2>(exp_ins).bytes, ins.bytes);
            EXPECT_EQ(std::get<2>(exp_ins).operands, ins.operands);
        }
        
        EXPECT_EQ(std::get<2>(exp_ins).id, ins.id);

        EXPECT_EQ(std::get<2>(exp_ins).mnemonic, ins.mnemonic);

        EXPECT_EQ(std::get<3>(exp_ins), label);
    }

    delete dbg;
}

#ifdef _WIN64
TEST(debugger_debug, x64)
{
    const std::vector<std::tuple<bool, bool, instruction, std::string>> expected =
    {
        { true, true, { 0x146, 0x401500, { 0x48, 0x83, 0xec, 0x28 }, "sub", "rsp, 0x28" }, { } }
    };
    
    test_file(TEST_FOLDER "helloworld64.exe", IMAGE_FILE_MACHINE_AMD64, expected);
}
#else
TEST(debugger_debug, x86)
{
    const std::vector<std::tuple<bool, bool, instruction, std::string>> expected =
    {
        { true,  true,  { 0x10a, 0x401000, { 0xeb, 0x10 },                         "jmp",  "0x401012",                  }, { }                           },
        { true,  true,  { 0x1ba, 0x401012, { 0xa1, 0xbf, 0x61, 0x41, 0x00 },       "mov",  "eax, dword ptr [0x4161bf]", }, { }                           },
        { true,  true,  { 0x283, 0x401017, { 0xc1, 0xe0, 0x02 },                   "shl",  "eax, 2",                    }, { }                           },
        { true,  true,  { 0x1ba, 0x40101a, { 0xa3, 0xc3, 0x61, 0x41, 0x00 },       "mov",  "dword ptr [0x4161c3], eax", }, { }                           },
        { true,  true,  { 0x244, 0x40101f, { 0x52 },                               "push", "edx",                       }, { }                           },
        { true,  true,  { 0x244, 0x401020, { 0x6a, 0x00 },                         "push", "0",                         }, { }                           },
        { true,  true,  { 0x038, 0x401022, { 0xe8, 0x65, 0x41, 0x01, 0x00 },       "call", "0x41518c",                  }, { }                           },
        { true,  true,  { 0x10a, 0x41518c, { 0xff, 0x25, 0x3c, 0x12, 0x42, 0x00 }, "jmp",  "dword ptr [0x42123c]",      }, { }                           },
        { false, true,  { 0x1ba, { },      { 0x8b, 0xff },                         "mov",  "edi, edi",                  }, "KERNEL32.GetModuleHandleA"   },
        { false, true,  { 0x244, { },      { 0x55 },                               "push", "ebp",                       }, { }                           },
        { false, true,  { 0x1ba, { },      { 0x8b, 0xec },                         "mov",  "ebp, esp",                  }, { }                           },
        { false, true,  { 0x22e, { },      { 0x5d },                               "pop",  "ebp",                       }, { }                           },
        { false, false, { 0x10a, { },      { },                                    "jmp",  { },                         }, { }                           },
        { false, true,  { 0x1ba, { },      { 0x8b, 0xff },                         "mov",  "edi, edi",                  }, "KERNELBASE.GetModuleHandleA" }
    };
    
    test_file(TEST_FOLDER "Test.exe", IMAGE_FILE_MACHINE_I386, expected);
}
#endif
