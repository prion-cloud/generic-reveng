#include "stdafx.h"

#include "control_flow.h"

enum class placeholder : char
{
    id = '#',
    next = '~'
};
static void replace_first(std::string& string, const placeholder placeholder, const std::string& substitute)
{
    const auto pos = string.find_first_of(static_cast<char>(placeholder));

    if (pos == std::string::npos)
        return;

    for (unsigned i = 0; i < substitute.size(); ++i)
        string = string.substr(0, pos + i) + substitute.at(i) + string.substr(pos + i + 1);
}
static std::string to_string_hex(const unsigned value)
{
    std::ostringstream ss;
    ss << std::hex << std::uppercase << value;
    return ss.str();
}

std::string control_flow::block::to_string(const bool prev, unsigned& mid) const
{
    const unsigned console_width = 120;

    const std::string l = "| ";
    const std::string r = " |";

    const auto h = '-';

    const auto eu = '.';
    const auto ed = '\'';

    const auto mid_top = '^';
    const auto mid_bottom = 'v';

    std::ostringstream ss;

    const auto first = instruction_sequence->front();
    const auto first_string = first.to_string(true);
    const auto last = instruction_sequence->back();
    const auto last_string = last.to_string(true);

    const auto inner_width = first_string.size() > last_string.size() ? first_string.size() : last_string.size();
    const auto outer_width = inner_width + l.size() + r.size();

    const auto h_width = outer_width - 2;

    const auto padding = console_width / 2 - outer_width / 2;
    const auto mid_add = h_width / 2 - (h_width + 1) % 2;

    mid = padding + mid_add + 1;

    ss << std::string(padding, ' ') << static_cast<char>(placeholder::id);
    if (prev)
        ss << std::string(mid_add, h) << mid_top << std::string(h_width / 2, h);
    else ss << std::string(h_width, h);
    ss << eu << std::endl;
    // << std::setfill(h)
    // << std::setw(width + l.size() + r.size() - 2) << std::left << "(" + std::to_string(instruction_sequence->size()) + ")"
    // << eu << std::endl;

    ss << std::setfill(' ');

    if (instruction_sequence->size() > 1)
        ss << std::string(padding, ' ') << l << std::setw(inner_width) << std::left << first_string << r << std::endl;
    if (instruction_sequence->size() > 2)
        ss << std::string(padding, ' ') << l << std::setw(inner_width) << std::left << ':' << r << std::endl;

    ss << std::string(padding, ' ') << l << std::setw(inner_width) << std::left << last_string << r << std::endl;

    ss << std::string(padding, ' ') << ed;
    if (!next.empty())
        ss << std::string(mid_add, h) << mid_bottom << std::string(h_width / 2, h);
    else ss << std::string(h_width, h);
    ss << ed;

    //for (unsigned i = 0; i < next.size(); ++i)
    //    ss << ' ' << static_cast<char>(placeholder::next);

    return ss.str();
}

control_flow::control_flow(const disassembly& disassembly, const uint64_t start, const uint64_t stop)
{
    std::map<uint64_t, std::pair<block*, size_t>> map;
    std::map<block*, block*> redir;

    blocks_ = enumerate_blocks(build(disassembly, start, stop, map, redir));
}

void control_flow::draw() const
{
    std::map<unsigned, block const*> block_map;
    std::map<block const*, unsigned> id_map;

    unsigned id = 0;
    for (const auto& block : blocks_)
    {
        block_map.emplace(id, block);
        id_map.emplace(block, id);
        ++id;
    }

    auto first = true;
    for (const auto [id, block] : block_map)
    {
        const auto color = first || block->next.empty();
        if (color)
        {
            if (first)
                std::cout << dsp::colorize(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
            else if (block->next.empty())
                std::cout << dsp::colorize(FOREGROUND_RED | FOREGROUND_INTENSITY);
        }

        unsigned mid;
        auto block_string = block->to_string(!first, mid);

        replace_first(block_string, placeholder::id, to_string_hex(id));

        /*for (const auto next : block->next)
            replace_first(block_string, placeholder::next, id_map.at(next));*/
        
        if (!first)
            std::cout << std::endl;
        std::cout << block_string;
        for (const auto next : block->next)
            std::cout << " " << std::hex << std::uppercase << id_map.at(next);

        if (!block->next.empty())
        {
            std::cout << std::endl << std::string(mid, ' ') << '|';
        }

        if (color)
            std::cout << dsp::decolorize;

        /*if (block->next.empty())
            break;*/
        
        if (!first)
            break;

        first = false;
    }
}

std::vector<instruction_sequence> control_flow::get_blocks() const
{
    std::vector<instruction_sequence> result;
    for (const auto& block : blocks_)
        result.push_back(block->instruction_sequence);

    return result;
}

control_flow::block* control_flow::build(const disassembly& disassembly, uint64_t start, const uint64_t stop,
    std::map<uint64_t, std::pair<block*, size_t>>& map, std::map<block*, block*>& redir, data_flow data_flow)
{
    // New (current) block
    const auto cur = new block;

    // Tries to append an existing block at the specified address as successor
    const std::function<bool(uint64_t)> success = [cur, &map, &redir](const uint64_t next_address)
    {
        const auto map_it = map.find(next_address);
        if (map_it == map.end())
        {
            // No block exists at this address
            return false;
        }

        const auto [orig, index] = map_it->second;

        if (index == 0)
        {
            // Block does not have to be split
            cur->next.push_back(orig);
            return true;
        }

        const auto begin = orig->instruction_sequence->begin() + index;
        const auto end = orig->instruction_sequence->end();

        // Subsequent block
        const auto next = new block;

        // Copy tail
        next->instruction_sequence = instruction_sequence(std::vector<instruction>(begin, end));

        // Update map
        // TODO: Inefficient with large blocks
        for (auto j = 0; j < end - begin; ++j)
            map[(begin + j)->address] = std::make_pair(next, j);

        // Truncate tail
        orig->instruction_sequence->erase(begin, end);

        // Update successor information
        cur->next.push_back(next);
        next->next = orig->next;
        orig->next.clear();
        orig->next.push_back(next);

        // Redirect following successor declarations
        redir[orig] = next;

        return true;
    };

    // Repeat until successors are set
    while (cur->next.empty())
    {
        // Map address to block and index
        map.emplace(start, std::make_pair(cur, cur->instruction_sequence->size()));

        // Disassemble instruction
        const auto instruction = disassembly[start];

        // Append instruction
        cur->instruction_sequence->push_back(instruction);

        // Apply data flow
        data_flow.apply(instruction);

        if (instruction.address == stop)
        {
            // Reached final instruction, stop without successor
            break;
        }

        // Inspect possible jump results
        auto next_addresses = data_flow.inspect_rip();

        if (next_addresses.empty())
        {
            // TODO: Use emulation to go on
            throw;
        }

        if (next_addresses.size() > 1)// || instruction.is_jump())
        {
            // Reset a prior redirection
            redir[cur] = cur;

            for (const auto address : next_addresses)
            {
                if (!success(address))
                {
                    // Recursively create a new successor
                    const auto next = build(disassembly, address, stop, map, redir, data_flow);

                    // React to eventual redirections
                    redir[cur]->next.push_back(next);
                }
            }
        }
        else
        {
            const auto next_address = next_addresses.front();

            // Try to find existing successor
            if (!success(next_address))
            {
                // Advance current address and continue
                start = next_address;
            }
        }
    }

    return cur;
}

std::vector<control_flow::block*> control_flow::enumerate_blocks(block* root)
{
    std::queue<block*> queue;
    std::map<block*, bool> visited;
    std::vector<block*> blocks;

    queue.push(root);
    visited[root] = true;
    blocks.push_back(root);

    while (!queue.empty())
    {
        auto* const block = queue.front();
        queue.pop();

        for (const auto next : block->next)
        {
            if (visited[next])
                continue;

            queue.push(next);
            visited[next] = true;
            blocks.push_back(next);
        }
    }

    return blocks;
}
