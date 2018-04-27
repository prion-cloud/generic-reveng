#include "stdafx.h"
#include "macro.h"

TPL T emulator::mem_read(const uint64_t address) const
{
    return mem_read<T>(address, 0);
}
TPL T emulator::mem_read(const uint64_t address, const int index) const
{
    const auto size = sizeof(T);

    T value;
    E_FAT(uc_mem_read(uc_, address + index * size, &value, size));

    return value;
}

TPL void emulator::mem_write(const uint64_t address, const T value) const
{
    mem_write(address, value, 0);
}
TPL void emulator::mem_write(const uint64_t address, const T value, const int index) const
{
    const auto size = sizeof(T);
    E_FAT(uc_mem_write(uc_, address + index * size, &value, size));
}

TPL T emulator::reg_read(const regs reg) const
{
    T value;
    E_FAT(uc_reg_read(uc_, registers_.at(reg), &value));

    return value & scale_;
}
TPL void emulator::reg_write(const regs reg, T value) const
{
    E_FAT(uc_reg_write(uc_, registers_.at(reg), &value));
}
