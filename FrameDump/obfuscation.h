#pragma once

#include "disassembly.h"

class obfuscation_framed_x86
{
    const std::vector<disassembly_x86>* disassemblies_;

    const uint64_t base_address_;

    explicit obfuscation_framed_x86(const std::vector<disassembly_x86>* disassemblies, uint64_t base_address);

public:

    static std::vector<obfuscation_framed_x86> pick_all(const std::vector<disassembly_x86>* disassemblies);
};
