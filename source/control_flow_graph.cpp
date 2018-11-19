#include "../include/scout/control_flow_graph.h"

bool control_flow_graph::machine_instruction_comparator::operator()(
    machine_instruction const& instruction1,
    machine_instruction const& instruction2) const
{
    return instruction1.address < instruction2.address;
}

bool control_flow_graph::machine_instruction_comparator::operator()(
    machine_instruction const& instruction,
    uint64_t const address) const
{
    return instruction.address < address;
}
bool control_flow_graph::machine_instruction_comparator::operator()(
    uint64_t const address,
    machine_instruction const& instruction) const
{
    return address < instruction.address;
}

control_flow_graph::block::block(control_flow_graph const* cfg)
    : cfg_(cfg) { }

std::vector<control_flow_graph::block const*> control_flow_graph::block::successors() const
{
    auto const block_search = cfg_->block_map_.find(this);

    if (block_search == cfg_->block_map_.end())
        throw std::runtime_error("Invalid block");

    return block_search->second;
}

control_flow_graph::bfs_iterator::bfs_iterator(control_flow_graph const* base, block const* cur_block)
    : base_(base), cur_block_(cur_block) { }

bool control_flow_graph::bfs_iterator::operator==(bfs_iterator const& other) const
{
    return
        base_ == other.base_ &&
        cur_block_ == other.cur_block_;
}
bool control_flow_graph::bfs_iterator::operator!=(bfs_iterator const& other) const
{
    return !(operator==(other));
}

control_flow_graph::bfs_iterator& control_flow_graph::bfs_iterator::operator++()
{
    auto const& block_successors = base_->block_map_.find(cur_block_)->second;
    std::for_each(block_successors.cbegin(), block_successors.cend(),
        [this](auto const* block)
        {
            block_queue_.push(block);
        });

    previous_blocks_.insert(cur_block_);

    do
    {
        if (block_queue_.empty())
        {
            cur_block_ = nullptr;
            break;
        }

        cur_block_ = block_queue_.front();
        block_queue_.pop();
    }
    while (previous_blocks_.count(cur_block_) > 0);

    return *this;
}

control_flow_graph::bfs_iterator::reference control_flow_graph::bfs_iterator::operator*() const
{
    return cur_block_;
}

control_flow_graph::bfs_iterator control_flow_graph::begin() const
{
    return bfs_iterator(this, root_);
}
control_flow_graph::bfs_iterator control_flow_graph::end() const
{
    return bfs_iterator(this, nullptr);
}

control_flow_graph::block const* control_flow_graph::root() const
{
    return root_;
}

std::vector<std::vector<control_flow_graph::block const*>> control_flow_graph::get_layout() const
{
    std::vector<std::vector<block const*>> layout;

    for (auto const& [block, depth] : get_depths())
    {
        if (depth >= layout.size())
            layout.resize(depth + 1);

        layout.at(depth).push_back(block);
    }

    return layout;
}

std::unordered_map<control_flow_graph::block const*, size_t> control_flow_graph::get_depths() const
{
    std::unordered_map<block const*, size_t> depths;
    std::unordered_set<block const*> visited;

    get_depths(root_, depths, visited);

    return depths;
}
void control_flow_graph::get_depths(block const* root,
    std::unordered_map<block const*, size_t>& depths,
    std::unordered_set<block const*>& visited) const
{
    visited.insert(root);

    auto const root_depth = depths[root];

    for (auto const* next : root->successors())
    {
        if (visited.count(next) > 0)
            continue;

        auto& next_depth = depths[next];

        if (next_depth > root_depth)
            continue;

        next_depth = root_depth + 1;

        get_depths(next, depths, visited);
    }

    visited.erase(root);
}
