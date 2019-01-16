#pragma once

#include <memory>
#include <vector>

#include <capstone/capstone.h>

#include "machine_architecture.hpp"

using instruction = cs_insn;

class disassembler : public std::shared_ptr<csh>
{
    std::shared_ptr<csh> cs_;

public:

    explicit disassembler(machine_architecture const& architecture);

    std::shared_ptr<cs_insn> operator()(std::vector<uint8_t>* code, uint64_t* address) const;
};
