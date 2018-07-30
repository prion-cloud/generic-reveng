#include "catch2/catch.hpp"
#include "helper.h"

#include "capstone.h"

#define TAG_CAPSTONE "[capstone]"

TEST_CASE("Disassembling", TAG_CAPSTONE)
{
    test_data<std::vector<uint8_t>, std::vector<std::pair<std::string, std::string>>> test_data;
    test_data.add(
        { 0x48, 0x83, 0xEC, 0x28, 0x41, 0x53, 0x53, 0x5A, 0xC3 },
        {
            { "sub",  "rsp, 0x28" },
            { "push", "r11" },
            { "push", "rbx" },
            { "pop",  "rdx" },
            { "ret",  "" },
        });

    csh cs;
    cs_open(CS_ARCH_X86, CS_MODE_64, &cs);

    for (const auto& [in, out] : *test_data)
    {
        cs_insn* insn;
        const auto count = cs_disasm(cs, &in.front(), in.size(), 0, 0, &insn);

        REQUIRE(count == out.size());

        for (unsigned i = 0; i < count; ++i)
        {
            CHECK(insn[i].mnemonic == out.at(i).first);
            CHECK(insn[i].op_str == out.at(i).second);
        }
    }

    cs_close(&cs);
}
