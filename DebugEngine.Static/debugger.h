#pragma once

#include "disassembler.h"
#include "emulator.h"

#include "loader.h"

// Low-level debugger of executable binaries
class debugger
{
    disassembler* disassembler_;
    emulator* emulator_;

    std::map<uint64_t, std::pair<std::string, std::string>> sections_;
    std::map<uint64_t, std::string> labels_;

public:
    
    // Uses a loader to make some machine code ready for debugging.
    explicit debugger(loader* loader, uint16_t machine, std::vector<uint8_t> byte_vec);
    // Ends debugging and releases resources.
    ~debugger();

    // Emulates the next machine code instruction.
    int debug(instruction& instruction, std::string& label, std::map<std::string, uint64_t>& registers) const;
};
