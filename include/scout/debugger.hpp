#pragma once

#include <istream>
#include <memory>
#include <set>
#include <unordered_map>
#include <vector>

#include <scout/instruction.hpp>

#include <capstone.h>
#include <unicorn/unicorn.h>

class debugger
{
    struct executable_specification
    {
        std::pair<cs_arch, uc_arch> machine_architecture;
        std::pair<cs_mode, uc_mode> machine_mode;

        uint64_t entry_point { };

        std::unordered_map<uint64_t, std::vector<uint8_t>> memory_regions;
    };

    std::shared_ptr<csh> cs_;
    std::shared_ptr<uc_engine> uc_;

    int ip_register_;

public:

    debugger(debugger const&) = delete;
    debugger& operator=(debugger const&) = delete;

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
    machine_instruction current_instruction() const;

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

    uint64_t read_register(int id) const;
    void write_register(int id, uint64_t value);

    void allocate_memory(uint64_t address, size_t size);
    void allocate_memory(uint64_t address, std::vector<uint8_t> const& data);

    std::vector<uint8_t> read_memory(uint64_t address, size_t size) const;
    void write_memory(uint64_t address, std::vector<uint8_t> const& data);

    std::set<uc_mem_region> get_memory_regions() const;

    cs_err get_cs_error() const;
    uc_err get_uc_error() const;

    static debugger load_pe(std::istream& is);
    static debugger load_elf(std::istream& is);
};
