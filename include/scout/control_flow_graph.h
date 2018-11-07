#pragma once

#include <memory>
#include <map>
#include <vector>

#include "debugger.h"

class control_flow_graph
{
    using block = std::vector<machine_instruction>;
    using block_ptr = std::shared_ptr<block>;

    class block_ptr_comparator
    {
    public:

        using is_transparent = void;

        bool operator()(block_ptr const& block1, block_ptr const& block2) const;

        bool operator()(block_ptr const& block, uint64_t address) const;
        bool operator()(uint64_t address, block_ptr const& block) const;
    };

    block_ptr root_;

    std::map<block_ptr, std::vector<block_ptr>, block_ptr_comparator> block_map_;

public:

    explicit control_flow_graph(debugger const& debugger);

    std::vector<block const*> get_blocks() const;

private:

    static block_ptr build(debugger const& debugger,
        std::map<block_ptr, std::vector<block_ptr>, block_ptr_comparator>& block_map);
};
