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

bool control_flow_graph::block_ptr_comparator::operator()(
    block_ptr const& block1,
    block_ptr const& block2) const
{
    return block1->crbegin()->address < block2->cbegin()->address;
}

bool control_flow_graph::block_ptr_comparator::operator()(block_ptr const& block1, block const* block2) const
{
    return block1->crbegin()->address < block2->crbegin()->address;
}
bool control_flow_graph::block_ptr_comparator::operator()(block const* block1, block_ptr const& block2) const
{
    return block1->crbegin()->address < block2->crbegin()->address;
}

bool control_flow_graph::block_ptr_comparator::operator()(
    block_ptr const& block,
    uint64_t const address) const
{
    return block->crbegin()->address < address;
}
bool control_flow_graph::block_ptr_comparator::operator()(
    uint64_t const address,
    block_ptr const& block) const
{
    return address < block->cbegin()->address;
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
        [this](auto const& block)
        {
            block_queue_.push(block.get());
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
    return bfs_iterator(this, first_block_.get());
}
control_flow_graph::bfs_iterator control_flow_graph::end() const
{
    return bfs_iterator(this, nullptr);
}

std::vector<control_flow_graph::block const*> control_flow_graph::get_successors(block const* block) const
{
    auto const block_search = block_map_.find(block);

    if (block_search == block_map_.end())
        throw std::runtime_error("Invalid block");

    std::vector<control_flow_graph::block const*> successors(block_search->second.size());
    std::transform(block_search->second.cbegin(), block_search->second.cend(), successors.begin(),
        [](auto const& block)
        {
            return block.get();
        });

    return successors;
}
