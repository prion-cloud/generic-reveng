#pragma once

class control_flow_graph_x86
{
    struct block
    {
        std::vector<instruction_x86> instructions;

        std::set<block*> previous;
        std::vector<std::pair<std::optional<x86_insn>, block*>> next;

        std::string to_string() const;
    };

    struct path
    {
        std::vector<x86_insn> conditions;
        std::vector<block*> blocks;
    };

    std::map<uint64_t, std::pair<block*, size_t>> map_;

    std::vector<path> paths_;

public:

    control_flow_graph_x86(const std::shared_ptr<debugger>& debugger, uint64_t root_address);

    void draw() const;

private:

    static block* build(const std::shared_ptr<debugger>& debugger, uint64_t address, const std::vector<uint8_t>& stop,
        std::map<uint64_t, std::pair<block*, size_t>>& map, std::map<block*, block*>& redir);

    static std::vector<path> enumerate_paths(block* root, std::map<block*, bool> map = { },
        std::vector<x86_insn> conditions = { }, std::vector<block*> passed = { });

    friend bool operator<(const block& block1, const block& block2);
};
