#pragma once

#include "../DebugEngine.Static/emulator.h"

#include "instruction.h"
#include "../DebugEngine.Static/loader.h"

/*
class disassembly_part_x86
{
    uint64_t virtual_base_;

    std::vector<instruction_x86> instructions_;
    std::vector<uint8_t> code_;

public:

    explicit disassembly_part_x86();

    uint64_t base() const;
    size_t size() const;
    const void* nipple() const;

    bool find(uint64_t address, instruction_x86& instruction) const;

    void load(std::string file_name);
    void save(std::string file_name) const;

    std::set<uint64_t> crawl_sequences(int min, unsigned find, std::set<unsigned> add) const;

    static disassembly_part_x86 create_complete(uint64_t virtual_base, uint64_t raw_address, std::vector<uint8_t> code);

private:
    
    explicit disassembly_part_x86(uint64_t virtual_base, std::vector<instruction_x86> instructions, std::vector<uint8_t> code);
};

class disassembly_x86
{
    csh cs_;
    uc_engine* uc_;

    //std::vector<disassembly_part_x86> parts_;

    loader_pe loader_;

public:

    disassembly_x86();
    ~disassembly_x86();

    csh cs() const;
    uc_engine* uc() const;

    void load_part(std::string file_name);

    instruction_x86 find(uint64_t address) const;
    
    std::set<uint64_t> crawl_sequences(int min, unsigned find, std::set<unsigned> add) const;
};
*/
