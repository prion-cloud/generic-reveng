#pragma once

#include "memory_monitor.h"

class control_flow_graph_x86
{
    struct node
    {
        traceback_x86 traceback;

        std::vector<node*> previous;
        std::vector<node*> next;
    };

    node* root_;

    std::map<uint64_t, node*> node_map_;

    memory_monitor monitor_;

public:

    control_flow_graph_x86(const std::shared_ptr<debugger>& debugger, uint64_t root_address);

    traceback_x86 find_traceback(uint64_t address) const;

private:

    node* build(std::shared_ptr<debugger> debugger, uint64_t address, std::vector<uint8_t> stop);
};
