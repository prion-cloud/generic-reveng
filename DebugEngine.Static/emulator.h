#pragma once

#include "../Bin-Unicorn/unicorn.h"

#define PAGE_SIZE 0x1000

#define REG_COUNT 9

enum regs
{
    reg_ax, reg_bx, reg_cx, reg_dx,
    reg_sp, reg_bp,
    reg_si, reg_di,
    reg_ip
};

class emulator
{
    uc_engine* uc_;

    uint64_t scale_;

    std::map<int, int> registers_;

public:

    explicit emulator(WORD machine);
    ~emulator();
    
    void mem_map(uint64_t address, void* buffer, size_t size) const;
    
    TPL T mem_read(uint64_t address) const;
    TPL T mem_read(uint64_t address, int index) const;
    
    void mem_read(uint64_t address, void* buffer, size_t size) const;
    
    std::string mem_read_string(uint64_t address) const;

    TPL void mem_write(uint64_t address, T value) const;
    TPL void mem_write(uint64_t address, T value, int index) const;

    TPL T reg_read(regs reg) const;
    TPL void reg_write(regs reg, T value) const;

    void jump(uint64_t address) const;

    void run() const;

    void step_into() const;
    void step_over() const;
};

#include "emulator_tpl.cpp"
