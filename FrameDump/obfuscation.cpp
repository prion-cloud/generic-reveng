#include "stdafx.h"

#include "obfuscation.h"

obfuscation_framed_x86::obfuscation_framed_x86(const disassembly_x86* disassembly, const uint64_t address)
    : disassembly_(disassembly), address_(address), control_flow_(disassembly_, address_) { }

void obfuscation_framed_x86::test() const
{
    control_flow_.next();
}

std::vector<obfuscation_framed_x86> obfuscation_framed_x86::pick_all(const disassembly_x86* disassembly)
{
    std::vector<obfuscation_framed_x86> obfuscations;
    for (const auto address : disassembly->crawl_sequences(10, X86_INS_PUSH, { X86_INS_PUSHFQ, X86_INS_MOVUPD, X86_INS_LEA }))
        obfuscations.push_back(obfuscation_framed_x86(disassembly, address));

    return obfuscations;
}
