#pragma once

#include <istream>
#include <unordered_map>
#include <vector>

#include "../../submodules/capstone/include/capstone.h"
#include "../../submodules/unicorn/include/unicorn/unicorn.h"

struct load_data
{
    std::pair<cs_arch, uc_arch> machine_architecture;
    std::pair<cs_mode, uc_mode> machine_mode;

    uint64_t entry_point { };

    std::unordered_map<uint64_t, std::vector<uint8_t>> memory_regions;
};

load_data load(std::istream& is);
