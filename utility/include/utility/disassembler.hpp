#pragma once

#include <memory>
#include <vector>

#include <capstone/capstone.h>

#include "machine_architecture.hpp"

class disassembler : public std::shared_ptr<csh>
{
public:

    explicit disassembler(machine_architecture const& architecture);

    cs_insn operator()(std::vector<uint8_t>* code, uint64_t* address) const;
};
