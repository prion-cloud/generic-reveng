#include "stdafx.h"

#include "obfuscation.h"

obfuscation_x86::obfuscation_x86(const disassembly_x86* disassembly, const uint64_t address)
    : disassembly_(disassembly), address_(address), current_(disassembly_, address_, code_constraint::none()) { }

void obfuscation_x86::emerge_calls()
{
    const auto instruction = current_.instruction();

    if (instruction.address() == 0x3D7B29)
        return;

    instructions.push_back(current_.instruction());

    std::optional<assignment> asgn;
    const auto next = current_.next(asgn);

    for (const auto n : next)
    {
        current_ = n;
        emerge_calls(instructions);
    }
}

/*
void obfuscation_x86::test()
{
    auto n = control_flow_;

    for (auto i = 0; i < 50; ++i)
    {
        std::optional<assignment> asgn;
        n = n.next(asgn).at(0);

        if (asgn.has_value())
            taints_[asgn->destination] = var_expr(asgn->source);
    }
}
*/

std::vector<obfuscation_x86> obfuscation_x86::pick_all(const disassembly_x86* disassembly)
{
    std::vector<obfuscation_x86> obfuscations;
    for (const auto address : disassembly->crawl_sequences(10, X86_INS_PUSH, { X86_INS_PUSHFQ, X86_INS_MOVUPD, X86_INS_LEA }))
        obfuscations.push_back(obfuscation_x86(disassembly, address));

    return obfuscations;
}
