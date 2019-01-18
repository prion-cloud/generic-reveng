#pragma once

#include <memory>
#include <vector>

#include <unicorn/unicorn.h>

#include "machine_architecture.hpp"

class emulator
{
public:

    using architecture = uc_arch;
    using mode = uc_mode;

private:

    struct uc_deleter
    {
        void operator()(uc_engine** uc) const;
    };

    std::unique_ptr<uc_engine*, uc_deleter> uc_;

    int ip_register_;

public:

    emulator();
    emulator(architecture architecture, mode mode, int ip_register);

    uint64_t position() const;
    void position(uint64_t address) const;

    void map_memory(uint64_t address, size_t size) const;

    std::vector<uint8_t> read_memory(uint64_t address, size_t size) const;
    void write_memory(uint64_t address, std::vector<uint8_t> const& data) const;

    void operator()() const;

private:

    uint64_t read_register(int id) const;
    void write_register(int id, uint64_t value) const;
};
