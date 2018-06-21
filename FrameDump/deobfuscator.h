#pragma once

class obfuscation_graph_x86
{
    struct node
    {
        std::shared_ptr<instruction_x86> instruction;

        node* previous;
        std::vector<node*> next;

        node() = default;
        node(std::shared_ptr<debugger> debugger, uint64_t address, std::vector<uint8_t> stop,
            std::map<uint64_t, node*>& node_map, uint64_t& stop_address, node* previous = nullptr, bool last_error = false);
    };

    uint64_t root_address_;
    uint64_t stop_address_;

    node root_;

    std::map<uint64_t, node*> node_map_;

public:

    obfuscation_graph_x86(std::shared_ptr<debugger> debugger, uint64_t root_address);

    instruction_x86 find_instruction(uint64_t address);
};

class deobfuscator_x86
{
    std::shared_ptr<debugger> debugger_;

public:

    explicit deobfuscator_x86(loader& loader, std::vector<uint8_t> code);

    std::vector<obfuscation_graph_x86> inspect_framed(std::vector<uint64_t> addresses) const;
};
