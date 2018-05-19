#pragma once

#include "disassembler.h"
#include "emulator.h"

#include "loader.h"

#define MAX_TRACE 5

struct debug_trace_entry
{
    uint64_t address;

    int error;
    std::string error_str;

    std::map<x86_reg, uint64_t> old_registers;
    std::map<std::string, uint64_t> new_registers;
};

// Low-level debugger of executable binaries
class debugger
{
    loader& loader_;

    std::unique_ptr<disassembler> disassembler_;
    std::shared_ptr<emulator> emulator_;

    std::shared_ptr<instruction> next_instruction_;

    std::deque<debug_trace_entry> trace_;

    std::set<uint64_t> breakpoints_;

public:
    
    // Uses a loader to make some machine code ready for debugging.
    explicit debugger(loader& loader, std::vector<uint8_t> code);

    std::shared_ptr<instruction> next_instruction() const;

    // Emulates the next machine code instruction.
    debug_trace_entry step_into();

    debug_trace_entry step_back();

    void set_breakpoint(uint64_t address);

    void jump_to(uint64_t address);
    void skip();

private:

    std::shared_ptr<instruction> disassemble_at(uint64_t address) const;
};
