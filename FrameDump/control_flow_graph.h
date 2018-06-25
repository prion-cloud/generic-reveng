#pragma once

class control_flow_graph_x86
{
    struct block
    {
        std::vector<instruction_x86> instructions;

        std::vector<block*> next;
    };

    block* root_;

    std::map<uint64_t, std::pair<block*, size_t>> map_;

public:

    control_flow_graph_x86(const std::shared_ptr<debugger>& debugger, uint64_t root_address);

    void draw() const;

private:

    static block* build(const std::shared_ptr<debugger>& debugger, uint64_t address, const std::vector<uint8_t>& stop,
        std::map<uint64_t, std::pair<block*, size_t>>& map);

    friend bool operator<(const block& block1, const block& block2);
};
