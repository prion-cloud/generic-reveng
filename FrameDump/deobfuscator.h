#pragma once

#include "memory_monitor.h"

class obfuscation_graph_x86
{
    struct node
    {
        traceback_x86 traceback;

        node* previous;
        std::vector<node*> next;

        node() = default;
        node(std::shared_ptr<debugger> debugger, uint64_t address, std::vector<uint8_t> stop,
            std::map<uint64_t, node*>& node_map, memory_monitor& monitor, uint64_t& stop_address,
            node* previous = nullptr);
    };

    uint64_t root_address_;
    uint64_t stop_address_;

    node root_;

    std::map<uint64_t, node*> node_map_;

    memory_monitor monitor_;

public:

    obfuscation_graph_x86(std::shared_ptr<debugger> debugger, uint64_t root_address);

    traceback_x86 find_traceback(uint64_t address) const;
};

class deobfuscator_x86
{
    std::shared_ptr<debugger> debugger_;

public:

    explicit deobfuscator_x86(loader& loader, std::vector<uint8_t> code);

    std::vector<obfuscation_graph_x86> inspect_framed(std::vector<uint64_t> addresses) const;
};
