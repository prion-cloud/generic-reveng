#include "stdafx.h"

static std::map<uc_x86_reg, uint64_t> reg_scales =
{
    { UC_X86_REG_RAX, UINT64_MAX },
    { UC_X86_REG_EAX, UINT32_MAX },
    { UC_X86_REG_AX, UINT16_MAX },
    { UC_X86_REG_AH, UINT8_MAX },
    { UC_X86_REG_AL, UINT8_MAX },
    
    { UC_X86_REG_RBX, UINT64_MAX },
    { UC_X86_REG_EBX, UINT32_MAX },
    { UC_X86_REG_BX, UINT16_MAX },
    { UC_X86_REG_BH, UINT8_MAX },
    { UC_X86_REG_BL, UINT8_MAX },
    
    { UC_X86_REG_RCX, UINT64_MAX },
    { UC_X86_REG_ECX, UINT32_MAX },
    { UC_X86_REG_CX, UINT16_MAX },
    { UC_X86_REG_CH, UINT8_MAX },
    { UC_X86_REG_CL, UINT8_MAX },
    
    { UC_X86_REG_RDX, UINT64_MAX },
    { UC_X86_REG_EDX, UINT32_MAX },
    { UC_X86_REG_DX, UINT16_MAX },
    { UC_X86_REG_DH, UINT8_MAX },
    { UC_X86_REG_DL, UINT8_MAX },
    
    { UC_X86_REG_RSI, UINT64_MAX },
    { UC_X86_REG_ESI, UINT32_MAX },
    { UC_X86_REG_SI, UINT16_MAX },
    { UC_X86_REG_SIL, UINT8_MAX },
    
    { UC_X86_REG_RDI, UINT64_MAX },
    { UC_X86_REG_EDI, UINT32_MAX },
    { UC_X86_REG_DI, UINT16_MAX },
    { UC_X86_REG_DIL, UINT8_MAX },
    
    { UC_X86_REG_RBP, UINT64_MAX },
    { UC_X86_REG_EBP, UINT32_MAX },
    { UC_X86_REG_BP, UINT16_MAX },
    { UC_X86_REG_BPL, UINT8_MAX },
    
    { UC_X86_REG_RSP, UINT64_MAX },
    { UC_X86_REG_ESP, UINT32_MAX },
    { UC_X86_REG_SP, UINT16_MAX },
    { UC_X86_REG_SPL, UINT8_MAX },

    { UC_X86_REG_R8, UINT64_MAX },
    { UC_X86_REG_R8D, UINT32_MAX },
    { UC_X86_REG_R8W, UINT16_MAX },
    { UC_X86_REG_R8B, UINT8_MAX },

    { UC_X86_REG_R9, UINT64_MAX },
    { UC_X86_REG_R9D, UINT32_MAX },
    { UC_X86_REG_R9W, UINT16_MAX },
    { UC_X86_REG_R9B, UINT8_MAX },

    { UC_X86_REG_R10, UINT64_MAX },
    { UC_X86_REG_R10D, UINT32_MAX },
    { UC_X86_REG_R10W, UINT16_MAX },
    { UC_X86_REG_R10B, UINT8_MAX },

    { UC_X86_REG_R11, UINT64_MAX },
    { UC_X86_REG_R11D, UINT32_MAX },
    { UC_X86_REG_R11W, UINT16_MAX },
    { UC_X86_REG_R11B, UINT8_MAX },

    { UC_X86_REG_R12, UINT64_MAX },
    { UC_X86_REG_R12D, UINT32_MAX },
    { UC_X86_REG_R12W, UINT16_MAX },
    { UC_X86_REG_R12B, UINT8_MAX },

    { UC_X86_REG_R13, UINT64_MAX },
    { UC_X86_REG_R13D, UINT32_MAX },
    { UC_X86_REG_R13W, UINT16_MAX },
    { UC_X86_REG_R13B, UINT8_MAX },

    { UC_X86_REG_R14, UINT64_MAX },
    { UC_X86_REG_R14D, UINT32_MAX },
    { UC_X86_REG_R14W, UINT16_MAX },
    { UC_X86_REG_R14B, UINT8_MAX },

    { UC_X86_REG_R15, UINT64_MAX },
    { UC_X86_REG_R15D, UINT32_MAX },
    { UC_X86_REG_R15W, UINT16_MAX },
    { UC_X86_REG_R15B, UINT8_MAX },

    { UC_X86_REG_ES, UINT16_MAX },
    { UC_X86_REG_CS, UINT16_MAX },
    { UC_X86_REG_SS, UINT16_MAX },
    { UC_X86_REG_DS, UINT16_MAX },
    { UC_X86_REG_FS, UINT16_MAX },
    { UC_X86_REG_GS, UINT16_MAX }
};

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

TPL T emulator::reg_read(const int regid) const
{
    T value;
    FATAL_IF(uc_reg_read(uc_, regid, &value));

    auto scale = max_scale_;

    const auto uc_reg = static_cast<uc_x86_reg>(regid);
    if (reg_scales.find(uc_reg) != reg_scales.end())
        scale = reg_scales.at(uc_reg);

    return value & scale;
}
TPL void emulator::reg_write(const int regid, T value) const
{
    FATAL_IF(uc_reg_write(uc_, regid, &value));
}
