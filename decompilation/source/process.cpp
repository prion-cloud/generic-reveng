#include <decompilation/process.hpp>

#include "disassembler.hpp"
#include "monitor.hpp"

dec::instruction
    get_instruction(dec::monitor& monitor, std::vector<reil_inst_t> const& intermediate_instructions)
{
    static std::unordered_map<reil_op_t, z3::expr (*)(z3::expr const&)> const unop
    {
        { I_NEG, z3::operator- },
        { I_NOT, z3::operator~ }
    };
    static std::unordered_map<reil_op_t, z3::expr (*)(z3::expr const&, z3::expr const&)> const binop
    {
        { I_ADD, z3::operator+ },
        { I_SUB, z3::operator- },
        { I_MUL, z3::operator* },
        { I_DIV, z3::operator/ },
        { I_MOD, z3::mod },
        { I_SMUL, z3::operator* }, // TODO
        { I_SDIV, z3::operator/ }, // TODO
        { I_SMOD, z3::mod }, // TODO
        { I_SHL, nullptr }, // TODO
        { I_SHR, nullptr }, // TODO
        { I_AND, z3::operator& },
        { I_OR, z3::operator| },
        { I_XOR, z3::operator^ },
        { I_EQ, z3::operator== },
        { I_LT, z3::operator< }
    };

    bool step(true);
    for (auto const& reil_instruction : intermediate_instructions)
    {
        auto const op = reil_instruction.op;

        auto const source_1 = reil_instruction.a;
        auto const source_2 = reil_instruction.b;

        auto const destination = reil_instruction.c;

        switch (op)
        {
        case I_NONE:
            break;
        case I_UNK:
            step = false;
            break;
        case I_JCC:
            step = reil_instruction.a.type != A_CONST || reil_instruction.a.val == 0;
            break;
        case I_STR:
            monitor.set(destination, monitor.get(source_1));
            break;
        case I_STM:
            // TODO
            break;
        case I_LDM:
            // TODO
            break;
        case I_NEG:
        case I_NOT:
            monitor.set(destination, unop.at(op)(monitor.get(source_1)));
            break;
        case I_ADD:
        case I_SUB:
        case I_MUL:
        case I_DIV:
        case I_MOD:
        case I_SMUL:
        case I_SDIV:
        case I_SMOD:
        case I_SHL:
        case I_SHR:
        case I_AND:
        case I_OR:
        case I_XOR:
        case I_EQ:
        case I_LT:
            monitor.set(destination, binop.at(op)(monitor.get(source_1), monitor.get(source_2)));
            break;
        }

        if (!step)
            break;
    }

    auto const& raw_info = intermediate_instructions.front().raw_info;

    return dec::instruction
    {
        .address = raw_info.addr,
        .size = static_cast<std::size_t>(raw_info.size),

        .impact = monitor.impact()
    };
}
std::unordered_set<std::uint_fast64_t>
    get_next_addresses(std::vector<reil_inst_t> const& intermediate_instructions)
{
    std::unordered_set<std::uint_fast64_t> next_addresses;

    bool step(true);
    for (auto const& reil_instruction : intermediate_instructions)
    {
        switch (reil_instruction.op)
        {
        case I_UNK:
            step = false;
            break;
        case I_JCC:
            switch (reil_instruction.c.type)
            {
            case A_LOC:
                next_addresses.insert(reil_instruction.c.val);
                break;
            default:
                // TODO
                break;
            }
            step = reil_instruction.a.type != A_CONST || reil_instruction.a.val == 0;
            break;
        default:
            break;
        }

        if (!step)
            break;
    }

    if (step)
        next_addresses.insert(intermediate_instructions.front().raw_info.addr + intermediate_instructions.front().raw_info.size);

    return next_addresses;
}

namespace dec
{
    process::process(std::vector<std::uint_fast8_t> data, instruction_set_architecture const architecture) :
        memory_(std::move(data)),
        disassembler_(std::make_unique<disassembler const>(architecture)),
        monitor_(std::make_unique<monitor>())
    {
        execute_from(0);
    }
    process::~process() = default;
    
    std::set<instruction_block, instruction_block::exclusive_address_order> const& process::blocks() const
    {
        return blocks_;
    }
    std::unordered_map<std::uint_fast64_t, std::unordered_set<std::uint_fast64_t>> const& process::block_map() const
    {
        return block_map_;
    }

    void process::execute_from(std::uint_fast64_t address)
    {
        // Use the start address of the next higher block as a maximum
        std::optional<std::uint_fast64_t> max_address;
        if (auto const max_block = blocks_.lower_bound(address); max_block != blocks_.end())
            max_address = max_block->begin()->address;

        // Fill a new block with contiguous instructions
        instruction_block new_block;
        std::unordered_set<std::uint_fast64_t> next_addresses;
        do
        {
            auto const intermediate_instructions = disassembler_->read(address, memory_[address]);

            auto instruction = get_instruction(*monitor_, intermediate_instructions);
            address += instruction.size;

            new_block.insert(new_block.end(), std::move(instruction));
            next_addresses = get_next_addresses(intermediate_instructions);
        }
        while (
            // Single successor
            next_addresses.size() == 1 &&
            // Directly following
            *next_addresses.begin() == address &&
            // Block size integrity
            (!max_address || *next_addresses.begin() < max_address));

        auto const& [current_block, current_block_original] =
            blocks_.insert(std::move(new_block));
        if (!current_block_original)
            throw std::logic_error("");

        auto const& [current_block_map_entry, current_block_map_entry_original] =
            block_map_.emplace(current_block->begin()->address, std::move(next_addresses));
        if (!current_block_map_entry_original)
            throw std::logic_error("");

        for (auto const& next_address : current_block_map_entry->second)
        {
            // Search for an existing block already covering the next address
            auto const existing_block = blocks_.lower_bound(next_address);

            // No block found?
            if (existing_block == blocks_.upper_bound(next_address))
            {
                // RECURSE with this successor
                execute_from(next_address);
                continue;
            }

            // Search for the respective instruction in the found block
            auto const existing_instruction = existing_block->find(next_address);
            if (existing_instruction == existing_block->end())
                throw std::logic_error("");

            // Is it the first instruction?
            if (existing_instruction == existing_block->begin())
                continue;

            auto const existing_block_hint = std::next(existing_block);

            instruction_block existing_head_block;
            auto existing_tail_block = blocks_.extract(existing_block);
            while (existing_tail_block.value().begin() != existing_instruction)
                existing_head_block.insert(
                    existing_head_block.begin(),
                    existing_tail_block.value().extract(std::prev(existing_instruction)));

            auto existing_head_block_map_entry = block_map_.extract(existing_head_block.begin()->address);
            std::pair existing_tail_block_map_entry
            {
                existing_tail_block.value().begin()->address,
                std::move(existing_head_block_map_entry.mapped())
            };
            existing_head_block_map_entry.mapped() =
                std::unordered_set
                {
                    existing_tail_block.value().begin()->address
                };

            blocks_.insert(existing_block_hint, std::move(existing_head_block));
            blocks_.insert(existing_block_hint, std::move(existing_tail_block));

            block_map_.insert(std::move(existing_head_block_map_entry));
            block_map_.insert(std::move(existing_tail_block_map_entry));
        }
    }

    static_assert(std::is_destructible_v<process>);

    static_assert(!std::is_move_constructible_v<process>); // TODO
    static_assert(!std::is_move_assignable_v<process>); // TODO

    static_assert(!std::is_copy_constructible_v<process>); // TODO
    static_assert(!std::is_copy_assignable_v<process>); // TODO
}
