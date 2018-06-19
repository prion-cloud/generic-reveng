#pragma once

#include "../DebugEngine.Static/debugger.h"

class obfuscation_graph_x86
{
    class node
    {
        std::shared_ptr<instruction> instruction_;

        std::vector<std::shared_ptr<node>> next_;

    public:

        explicit node(std::shared_ptr<debugger> debugger, uint64_t address, uint64_t stop_address,
            std::map<uint64_t, node*>& nodes, bool last_error);
    };

    node root_;

    explicit obfuscation_graph_x86(node root);

public:

    static obfuscation_graph_x86 build(std::shared_ptr<debugger> debugger, uint64_t root_address, uint64_t stop_address);
};

class deobfuscator_x86
{
    std::shared_ptr<debugger> debugger_;

public:

    explicit deobfuscator_x86(loader& loader, std::vector<uint8_t> code);

    void build(uint64_t start, uint64_t stop) const;
};
