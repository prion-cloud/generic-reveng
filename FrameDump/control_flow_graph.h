#pragma once

class control_flow_graph_x86
{
    struct node
    {
        instruction_x86 instruction;

        std::vector<node*> previous { };
        std::vector<node*> next { };
    };

    node* root_ { };

    std::map<uint64_t, node*> node_map_ { };


public:

    control_flow_graph_x86(const std::shared_ptr<debugger>& debugger, uint64_t root_address);

private:

    static node* build(const std::shared_ptr<debugger>& debugger, uint64_t address, std::vector<uint8_t> stop,
        std::map<uint64_t, node*>& node_map, std::set<path>& paths);
};
