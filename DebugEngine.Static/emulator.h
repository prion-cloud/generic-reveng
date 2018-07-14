#pragma once

#include "../Bin-Unicorn/unicorn.h"
#include "../Bin-Capstone/x86.h"

#define PAGE_SIZE 0x1000

#define REG64_DEFAULT 0xDEF

// --- TODO Q&D
struct context
{
    uint64_t instruction_pointer { };

    uint64_t stack_pointer { }, base_pointer { };
    std::vector<uint8_t> stack_data;

    std::map<x86_reg, uint64_t> register_values;
};
// ---

class emulator
{
    uc_engine* uc_ { };

    std::set<uc_mem_region> mem_regions_;

    uint64_t max_scale_;

    x86_reg reg_sp_id_;
    x86_reg reg_bp_id_;

    x86_reg reg_ip_id_;

    // --- TODO Q&D
    uint64_t stack_size_;
    uint64_t stack_top_;
    // ---

public:

    explicit emulator(uint16_t machine/*-->*/, uint64_t stack_size, uint64_t stack_top/*<-- TODO Q&D*/);
    ~emulator();

    // Memory

    void mem_map(uint64_t address, const std::vector<uint8_t>& buffer, bool map = true/*TODO Q&D*/);

    bool mem_is_mapped(uint64_t address) const;

    TPL T mem_read(uint64_t address) const;
    TPL T mem_read(uint64_t address, int index) const;
    
    void mem_read(uint64_t address, std::vector<uint8_t>& buffer) const;
    
    std::string mem_read_string(uint64_t address) const;

    TPL void mem_write(uint64_t address, T value) const;
    TPL void mem_write(uint64_t address, T value, int index) const;

    // --- TODO Q&D
    context get_context() const;
    void set_context(context context);
    // ---

    // Registers

    TPL T reg_read(x86_reg regid) const;
    TPL void reg_write(x86_reg regid, T value) const;

    uint64_t address() const;
    void jump_to(uint64_t address) const;

    void resize_stack(uint64_t pointer) const;

    // Emulation

    int emulate_any() const;
    int emulate_once() const;

private:

    void initialize_registers() const;

    const std::map<x86_reg, uint64_t> register_map_ =
    {
        { X86_REG_RIP, UINT64_MAX },
        { X86_REG_EIP, UINT32_MAX },
        { X86_REG_IP, UINT16_MAX },

        { X86_REG_RAX, UINT64_MAX },
        { X86_REG_EAX, UINT32_MAX },
        { X86_REG_AX, UINT16_MAX },
        { X86_REG_AH, UINT8_MAX },
        { X86_REG_AL, UINT8_MAX },

        { X86_REG_RBX, UINT64_MAX },
        { X86_REG_EBX, UINT32_MAX },
        { X86_REG_BX, UINT16_MAX },
        { X86_REG_BH, UINT8_MAX },
        { X86_REG_BL, UINT8_MAX },

        { X86_REG_RCX, UINT64_MAX },
        { X86_REG_ECX, UINT32_MAX },
        { X86_REG_CX, UINT16_MAX },
        { X86_REG_CH, UINT8_MAX },
        { X86_REG_CL, UINT8_MAX },

        { X86_REG_RDX, UINT64_MAX },
        { X86_REG_EDX, UINT32_MAX },
        { X86_REG_DX, UINT16_MAX },
        { X86_REG_DH, UINT8_MAX },
        { X86_REG_DL, UINT8_MAX },

        { X86_REG_RSI, UINT64_MAX },
        { X86_REG_ESI, UINT32_MAX },
        { X86_REG_SI, UINT16_MAX },
        { X86_REG_SIL, UINT8_MAX },

        { X86_REG_RDI, UINT64_MAX },
        { X86_REG_EDI, UINT32_MAX },
        { X86_REG_DI, UINT16_MAX },
        { X86_REG_DIL, UINT8_MAX },

        { X86_REG_RBP, UINT64_MAX },
        { X86_REG_EBP, UINT32_MAX },
        { X86_REG_BP, UINT16_MAX },
        { X86_REG_BPL, UINT8_MAX },

        { X86_REG_RSP, UINT64_MAX },
        { X86_REG_ESP, UINT32_MAX },
        { X86_REG_SP, UINT16_MAX },
        { X86_REG_SPL, UINT8_MAX },

        { X86_REG_R8, UINT64_MAX },
        { X86_REG_R8D, UINT32_MAX },
        { X86_REG_R8W, UINT16_MAX },
        { X86_REG_R8B, UINT8_MAX },

        { X86_REG_R9, UINT64_MAX },
        { X86_REG_R9D, UINT32_MAX },
        { X86_REG_R9W, UINT16_MAX },
        { X86_REG_R9B, UINT8_MAX },

        { X86_REG_R10, UINT64_MAX },
        { X86_REG_R10D, UINT32_MAX },
        { X86_REG_R10W, UINT16_MAX },
        { X86_REG_R10B, UINT8_MAX },

        { X86_REG_R11, UINT64_MAX },
        { X86_REG_R11D, UINT32_MAX },
        { X86_REG_R11W, UINT16_MAX },
        { X86_REG_R11B, UINT8_MAX },

        { X86_REG_R12, UINT64_MAX },
        { X86_REG_R12D, UINT32_MAX },
        { X86_REG_R12W, UINT16_MAX },
        { X86_REG_R12B, UINT8_MAX },

        { X86_REG_R13, UINT64_MAX },
        { X86_REG_R13D, UINT32_MAX },
        { X86_REG_R13W, UINT16_MAX },
        { X86_REG_R13B, UINT8_MAX },

        { X86_REG_R14, UINT64_MAX },
        { X86_REG_R14D, UINT32_MAX },
        { X86_REG_R14W, UINT16_MAX },
        { X86_REG_R14B, UINT8_MAX },

        { X86_REG_R15, UINT64_MAX },
        { X86_REG_R15D, UINT32_MAX },
        { X86_REG_R15W, UINT16_MAX },
        { X86_REG_R15B, UINT8_MAX },

        { X86_REG_ES, UINT16_MAX },
        { X86_REG_CS, UINT16_MAX },
        { X86_REG_SS, UINT16_MAX },
        { X86_REG_DS, UINT16_MAX },
        { X86_REG_FS, UINT16_MAX },
        { X86_REG_GS, UINT16_MAX }
    };
};

#include "emulator_tpl.cpp"
