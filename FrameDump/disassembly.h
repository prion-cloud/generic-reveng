#pragma once

#include "instruction.h"

class disassembly_x86
{
    std::vector<instruction_x86> instructions_;

    explicit disassembly_x86(std::vector<instruction_x86> instructions);

public:

    void save(std::string file_name) const;

    std::set<uint64_t> find_sequences(int min, unsigned find, std::set<unsigned> add);
    std::map<uint64_t, std::vector<uint64_t>> find_immediates(std::set<uint64_t> imm, std::set<unsigned> consider);

    static disassembly_x86 create_complete(uint64_t base_address, std::vector<uint8_t> code);

    static disassembly_x86 load(std::string file_name);
};
