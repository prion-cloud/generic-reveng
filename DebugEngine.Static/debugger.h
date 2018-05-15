#pragma once

#include "disassembler.h"
#include "emulator.h"

#include "loader.h"

struct debug_trace_entry
{
    int error;
    std::string error_str;

    std::map<std::string, uint64_t> registers;
};

// Low-level debugger of executable binaries
class debugger
{
    loader& loader_;

    std::unique_ptr<disassembler> disassembler_;
    std::shared_ptr<emulator> emulator_;

    instruction next_instruction_;

    instruction disassemble_at(uint64_t address) const;

public:
    
    // Uses a loader to make some machine code ready for debugging.
    explicit debugger(loader& loader, std::vector<uint8_t> code);

    instruction next_instruction() const;

    // Emulates the next machine code instruction.
    debug_trace_entry step_into();

    void jump_to(uint64_t address);
    void skip();
};
