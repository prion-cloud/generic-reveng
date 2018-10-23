#pragma once

#include <istream>
#include <memory>
#include <vector>

#include "adapter_types.h"

#include "../../submodules/capstone/include/capstone.h"
#include "../../submodules/unicorn/include/unicorn/unicorn.h"

class debugger
{
    std::shared_ptr<uc_engine> uc_;

public:

    debugger(architecture architecture, mode mode);

    uint64_t position() const;

    void jump(uint64_t address) const;

    friend std::istream& operator>>(std::istream& is, debugger const& debugger);

private:

    uint64_t read_register(int id) const;
    void write_register(int id, uint64_t value) const;

    void allocate_memory(uint64_t address, size_t size) const;
    void allocate_memory(uint64_t address, std::vector<uint8_t> const& data) const;

    void read_memory(uint64_t address, std::vector<uint8_t>& data) const;
    void write_memory(uint64_t address, std::vector<uint8_t> const& data) const;
};
