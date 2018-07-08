#pragma once

#include "disassembly.h"

class frame_detector
{
    uint64_t base_address_;
    std::vector<uint8_t> const* code_;

    uint64_t position_;

public:

    explicit frame_detector(disassembly disassembly);

    void seek(uint64_t address);

    bool next(uint64_t& start, uint64_t& stop);
};
