#pragma once

#include "../Bin-Unicorn/unicorn.h"

#define PAGE_SIZE 0x1000

class emulator
{
    uc_engine* uc_;

    std::set<uc_mem_region> mem_regions_;

    uint64_t max_scale_;

    int reg_sp_id_;
    int reg_bp_id_;

    int reg_ip_id_;

public:

    explicit emulator(uint16_t machine);
    ~emulator();

    // Memory

    void mem_map(uint64_t address, std::vector<uint8_t> buffer);

    bool mem_is_mapped(uint64_t address) const;

    TPL T mem_read(uint64_t address) const;
    TPL T mem_read(uint64_t address, int index) const;
    
    void mem_read(uint64_t address, std::vector<uint8_t>& buffer) const;
    
    std::string mem_read_string(uint64_t address) const;

    TPL void mem_write(uint64_t address, T value) const;
    TPL void mem_write(uint64_t address, T value, int index) const;

    // Registers

    void init_regs(uint64_t stack_pointer, uint64_t instruction_pointer) const;

    TPL T reg_read(int regid) const;
    TPL void reg_write(int regid, T value) const;

    uint64_t address() const;
    void jump_to(uint64_t address) const;

    // Emulation

    int emulate_any() const;
    int emulate_once() const;
};

#include "emulator_tpl.cpp"
