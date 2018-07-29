#include "catch2/catch.hpp"
#include "helper.h"

#include "../source/data_flow.h"

#define TAG_DATA_FLOW "[data_flow]"

static cs_x86_op make_op(const x86_reg reg)
{
    cs_x86_op op { };
    op.type = X86_OP_REG;
    op.reg = reg;

    // ReSharper disable once CppSomeObjectMembersMightNotBeInitialized
    return op;
}

static cs_insn make_insn(const x86_insn id, const std::vector<cs_x86_op>& operands)
{
    cs_insn insn { };
    insn.id = id;

    cs_x86 x86 { };
    x86.op_count = static_cast<uint8_t>(operands.size());
    std::copy(operands.begin(), operands.end(), x86.operands);

    const auto detail = new cs_detail{};
    detail->x86 = x86;

    insn.detail = detail;

    return insn;
}

TEST_CASE("commit", TAG_DATA_FLOW)
{
    test_data<std::vector<cs_insn>, std::vector<std::pair<data_entry, data_entry>>> test_data;
    test_data.add(
        {
            make_insn(X86_INS_MOV, { make_op(X86_REG_RAX), make_op(X86_REG_RBX) })
        },
        {
            { X86_REG_RAX, X86_REG_RBX }
        }
    );

    for (const auto& [in, out] : *test_data)
    {
        data_flow data_flow;

        for (const auto& instruction : in)
            data_flow.commit(instruction);

        REQUIRE(data_flow.status() == out);
    }
}
