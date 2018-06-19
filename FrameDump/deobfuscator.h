#pragma once

#include "../DebugEngine.Static/debugger.h"

class obfuscation_graph_x86
{
    class node
    {
        std::shared_ptr<instruction> instruction_;
        std::vector<node*> next_;

    public:

        node() = default;
        node(std::shared_ptr<debugger> debugger, uint64_t address, std::pair<std::string, std::string> stop,
            std::map<uint64_t, node*>& nodes, uint64_t& stop_address, bool last_error = false);
    };

    uint64_t root_address_;
    uint64_t stop_address_;

    node root_;

public:

    obfuscation_graph_x86(std::shared_ptr<debugger> debugger, uint64_t root_address);
};

class deobfuscator_x86
{
    std::shared_ptr<debugger> debugger_;

public:

    explicit deobfuscator_x86(loader& loader, std::vector<uint8_t> code);

    std::vector<obfuscation_graph_x86> inspect_framed(std::vector<uint64_t> addresses) const;
};
