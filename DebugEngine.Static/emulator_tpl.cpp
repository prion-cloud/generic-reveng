#include "stdafx.h"

TPL T emulator::mem_read(const uint64_t address) const
{
    return mem_read<T>(address, 0);
}
TPL T emulator::mem_read(const uint64_t address, const int index) const
{
    const auto size = sizeof(T);

    T value;
    FATAL_IF(uc_mem_read(uc_, address + index * size, &value, size));

    return value;
}

TPL void emulator::mem_write(const uint64_t address, const T value) const
{
    mem_write(address, value, 0);
}
TPL void emulator::mem_write(const uint64_t address, const T value, const int index) const
{
    const auto size = sizeof(T);
    FATAL_IF(uc_mem_write(uc_, address + index * size, &value, size));
}

TPL T emulator::reg_read(x86_reg regid) const
{
    // --- BUG: Register IDs need conversion.
    if (regid > X86_REG_DR7)
        regid = static_cast<x86_reg>(static_cast<unsigned>(regid) + 8);
    // ---

    T value;
    FATAL_IF(uc_reg_read(uc_, regid, &value));

    auto scale = max_scale_;

    if (reg_scales.find(regid) != reg_scales.end())
        scale = reg_scales.at(regid);

    return value & scale;
}
TPL void emulator::reg_write(x86_reg regid, T value) const
{
    // --- BUG: Register IDs need conversion.
    if (regid > X86_REG_DR7)
        regid = static_cast<x86_reg>(static_cast<unsigned>(regid) + 8);
    // ---

    FATAL_IF(uc_reg_write(uc_, regid, &value));
}
