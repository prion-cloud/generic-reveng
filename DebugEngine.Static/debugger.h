#pragma once

#include "disassembler.h"
#include "emulator.h"

#include "loader.h"

// Low-level debugger of executable binaries
class debugger
{
    loader* loader_;

    disassembler* disassembler_;
    emulator* emulator_;

public:
    
    // Uses a loader to make some machine code ready for debugging.
    explicit debugger(loader* loader, std::vector<uint8_t> byte_vec);
    // Ends debugging and releases resources.
    ~debugger();

    // Emulates the next machine code instruction.
    int step_into(instruction& instruction, std::string& label, std::map<std::string, uint64_t>& registers) const;
};
