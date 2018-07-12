#pragma once

#include "data_flow.h"
#include "disassembly.h"
#include "instruction.h"

class control_flow
{
    struct block
    {
        instruction_sequence instruction_sequence;
        std::vector<block*> next;

        std::string to_string() const;
    };

    std::vector<block*> blocks_;

public:

    control_flow(const disassembly& disassembly, uint64_t start, uint64_t stop);

    void draw() const;

    std::vector<instruction_sequence> get_blocks() const;

private:

    static block* build(const disassembly& disassembly, uint64_t start, uint64_t stop,
        std::map<uint64_t, std::pair<block*, size_t>>& map, std::map<block*, block*>& redir, data_flow data_flow = { });

    static std::vector<block*> enumerate_blocks(block* root);
};
