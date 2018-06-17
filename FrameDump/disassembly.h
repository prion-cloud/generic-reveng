#pragma once

#include "../DebugEngine.Static/emulator.h"

#include "instruction.h"

class disassembly_part_x86
{
    std::vector<instruction_x86> instructions_;
    std::vector<uint8_t> code_;

    explicit disassembly_part_x86(std::vector<instruction_x86> instructions, std::vector<uint8_t> code);

public:

    uint64_t base() const;
    size_t size() const;
    const void* nipple() const;

    bool find(uint64_t address, instruction_x86& instruction) const;

    void save(std::string file_name) const;

    std::set<uint64_t> crawl_sequences(int min, unsigned find, std::set<unsigned> add) const;

    static disassembly_part_x86 create_complete(uint64_t base_address, std::vector<uint8_t> code);

    static disassembly_part_x86 load(std::string file_names);
};

class disassembly_x86
{
    uc_engine* uc_;

    std::vector<disassembly_part_x86> parts_;

public:

    disassembly_x86();
    ~disassembly_x86();

    uc_engine* uc() const;

    void add(disassembly_part_x86 part);

    instruction_x86 find(uint64_t address) const;
    
    std::set<uint64_t> crawl_sequences(int min, unsigned find, std::set<unsigned> add) const;
};
