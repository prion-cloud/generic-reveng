#include "stdafx.h"

#include "obfuscation.h"

obfuscation_framed_x86::obfuscation_framed_x86(const std::vector<disassembly_x86>* disassemblies, const uint64_t base_address)
    : disassemblies_(disassemblies), base_address_(base_address) { }

std::vector<obfuscation_framed_x86> obfuscation_framed_x86::pick_all(const std::vector<disassembly_x86>* disassemblies)
{
    std::vector<obfuscation_framed_x86> obfuscations;
    for (const auto disassembly : *disassemblies)
    {
        for (const auto address : disassembly.find_sequences(10, X86_INS_PUSH, { X86_INS_PUSHFQ, X86_INS_MOVUPD, X86_INS_LEA }))
            obfuscations.push_back(obfuscation_framed_x86(disassemblies, address));
    }

    return obfuscations;
}
