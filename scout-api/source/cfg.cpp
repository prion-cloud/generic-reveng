#include "cfg.hpp"

bool cfg::machine_instruction_compare::operator()(machine_instruction const& ins1, machine_instruction const& ins2) const
{
    return ins1.address < ins2.address;
}

bool cfg::machine_instruction_compare::operator()(machine_instruction const& ins, uint64_t const address) const
{
    return ins.address < address;
}
bool cfg::machine_instruction_compare::operator()(uint64_t const address, machine_instruction const& ins) const
{
    return address < ins.address;
}

bool cfg::block::operator<(block const& other) const
{
    return crbegin()->address < other.cbegin()->address;
}

bool operator<(cfg::block const& block, uint64_t const address)
{
    return block.crbegin()->address < address;
}
bool operator<(uint64_t const address, cfg::block const& block)
{
    return address < block.cbegin()->address;
}

cfg::block const* cfg::root() const
{
    return root_;
}

decltype(cfg::blocks_.begin()) cfg::begin() const
{
    return blocks_.begin();
}
decltype(cfg::blocks_.end()) cfg::end() const
{
    return blocks_.end();
}

std::unordered_map<size_t, std::unordered_map<size_t, cfg::block const*>> cfg::get_layout() const
{
    auto const columns = get_columns();
    auto const rows = get_rows();

    std::unordered_map<size_t, std::unordered_map<size_t, block const*>> layout;

    for (auto const& block : blocks_)
        layout[columns.at(block.get())][rows.at(block.get())] = block.get();

    return layout;
}

void get_columns(
    cfg::block const* root,
    std::unordered_map<cfg::block const*, size_t>& columns,
    std::unordered_set<cfg::block const*>& visited)
{
    visited.insert(root);

    auto const root_column = columns[root];

    auto next_column = root_column;
    for (auto const* const next : root->successors)
    {
        if (visited.count(next) > 0)
            continue;

        columns.emplace(next, next_column++);

        ::get_columns(next, columns, visited);
    }
}
std::unordered_map<cfg::block const*, size_t> cfg::get_columns() const
{
    std::unordered_map<block const*, size_t> columns;
    std::unordered_set<block const*> visited;

    ::get_columns(root_, columns, visited);

    return columns;
}

void get_rows(
    cfg::block const* root,
    std::unordered_map<cfg::block const*, size_t>& rows,
    std::unordered_set<cfg::block const*>& visited)
{
    visited.insert(root);

    auto const root_row = rows[root];

    for (auto const* const next : root->successors)
    {
        if (visited.count(next) > 0)
            continue;

        auto& next_row = rows[next];

        if (next_row > root_row)
            continue;

        next_row = root_row + 1;

        ::get_rows(next, rows, visited);
    }

    visited.erase(root);
}
std::unordered_map<cfg::block const*, size_t> cfg::get_rows() const
{
    std::unordered_map<block const*, size_t> rows;
    std::unordered_set<block const*> visited;

    ::get_rows(root_, rows, visited);

    return rows;
}
