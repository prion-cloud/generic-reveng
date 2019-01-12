#pragma once

#include <istream>
#include <memory>
#include <set>
#include <unordered_map>
#include <vector>

#include <utility/disassembler.hpp>
#include <utility/emulator.hpp>

class debugger
{
    struct executable_specification
    {
        machine_architecture architecture;

        uint64_t entry_point { };

        std::unordered_map<uint64_t, std::vector<uint8_t>> memory_regions;
    };

    disassembler disassembler_;
    emulator emulator_;

    int ip_register_;

public:

    /**
     * Reads the instruction pointer value.
     * \returns The current emulated memory address.
     */
    uint64_t position() const;
    /**
     * Edits the instruction pointer value.
     * \param [in] address The desired emulated memory address.
     * \returns True if the new address is mapped in emulated memory, otherwise false.
     */
    bool position(uint64_t address);

    /**
     * Inquires the current instruction.
     * \returns The machine instruction the instruction pointer currently points to.
     */
    cs_insn current_instruction() const;

    /**
     * Indicates whether the instruction pointer references mapped memory.
     * \return True if the pointed address is mapped in emulated memory, otherwise false.
     */
    bool is_mapped() const;
    /**
     * Indicates whether a memory address points to mapped memory.
     * \param [in] address The emulated memory address to be evaluated.
     * \returns True if the specified address is mapped in emulated memory, otherwise false.
     */
    bool is_mapped(uint64_t address) const;

    /**
     * Sets the instruction pointer to the next instruction without emulating the current one.
     * \returns True if the new address is mapped in emulated memory, otherwise false.
     */
    bool skip();
    /**
     * Advances the instruction pointer.
     * \param [in] count The number of bytes to be skipped.
     * \returns True if the new address is mapped in emulated memory, otherwise false.
     */
    bool skip(uint64_t count);

    /**
     * Emulates the current instruction.
     * \remarks Updates emulated registers and memory.
     * \returns True if the emulation was successful, otherwise false.
     */
    bool step_into();

    static debugger load(std::string const& file_name);
    static debugger load(std::istream& is);

private:

    explicit debugger(executable_specification const& specification);

    static debugger load_pe(std::istream& is);
    static debugger load_elf(std::istream& is);
};
