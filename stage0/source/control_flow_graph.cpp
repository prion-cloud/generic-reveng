#include <algorithm>

#include "control_flow_graph.hpp"

bool instruction_address_order::operator()(std::shared_ptr<instruction const> const& instructionA,
    std::shared_ptr<instruction const> const& instructionB) const
{
    return instructionA->address < instructionB->address;
}

bool instruction_address_order::operator()(std::shared_ptr<instruction const> const& instruction, uint64_t const address) const
{
    return instruction->address < address;
}
bool instruction_address_order::operator()(uint64_t const address, std::shared_ptr<instruction const> const& instruction) const
{
    return address < instruction->address;
}

control_flow_block::control_flow_block(disassembler const& disassembler, uint64_t address,
    std::optional<uint64_t> const& max_address, std::basic_string_view<uint8_t> code)
{
    // Fill the block with contiguous instructions
    std::vector<std::optional<uint64_t>> next_addresses;
    do
    {
        // Store current machine instruction
        insert(end(), disassembler(&address, &code));

        // Inquire successors
        next_addresses = get_next_addresses();
    }
    while (
        // Continue the block creation if
        !next_addresses.empty() && // - there current instruction has successors
        std::all_of(               // - that do not need jumps and
            next_addresses.cbegin(), next_addresses.cend(),
            [this](auto const& address)
            {
                auto const& instruction = *rbegin();
                return address &&
                    *address == instruction->address + instruction->size;
            }) &&
        (!max_address ||           // - the maximum block size is not yet reached
            *next_addresses.front() < max_address));
}

std::vector<std::optional<uint64_t>> control_flow_block::get_next_addresses() const
{
    auto const& instruction = **rbegin();

    // TODO only x86?

    auto const op0 = instruction.detail->x86.operands[0];

    std::vector<std::optional<uint64_t>> successors;

    switch (instruction.id)
    {
    case X86_INS_INT3:
    case X86_INS_INVALID:
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
        break;
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JB:
    case X86_INS_JBE:
    case X86_INS_JCXZ:
    case X86_INS_JE:
    case X86_INS_JG:
    case X86_INS_JGE:
    case X86_INS_JL:
    case X86_INS_JLE:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JS:
        successors.emplace_back(instruction.address + instruction.size);
    case X86_INS_JMP:
        switch (op0.type)
        {
        case X86_OP_IMM:
            successors.emplace_back(op0.imm);
            break;
        default:
            successors.emplace_back(std::nullopt);
            break;
        }
        break;
    default:
        successors.emplace_back(instruction.address + instruction.size);
        break;
    }

    return successors;
}

bool control_flow_block_exclusive_address_order::operator()(control_flow_block const& blockA,
    control_flow_block const& blockB) const
{
    return (*blockA.rbegin())->address < (*blockB.begin())->address;
}

bool control_flow_block_exclusive_address_order::operator()(control_flow_block const& block, uint64_t const address) const
{
    return (*block.rbegin())->address < address;
}
bool control_flow_block_exclusive_address_order::operator()(uint64_t const address, control_flow_block const& block) const
{
    return address < (*block.begin())->address;
}

control_flow_graph::control_flow_graph(disassembler disassembler,
    std::function<std::basic_string_view<uint8_t>(uint64_t)> GET_MEMORY, uint64_t const address)
    : disassembler_(std::move(disassembler)), GET_MEMORY_(std::move(GET_MEMORY))
{
    root_ = &construct(address);
}

control_flow_graph::node const& control_flow_graph::root() const
{
    return *root_;
}

control_flow_graph::node const& control_flow_graph::construct(uint64_t const address)
{
    // Use the start address of the next higher block as a maximum
    std::optional<uint64_t> max_address;
    auto const higher_block_search = lower_bound(address);
    if (higher_block_search != end())
        max_address = (*higher_block_search->first.begin())->address;

    // Create a new block
    auto const current_it = try_emplace(control_flow_block(disassembler_, address, max_address, GET_MEMORY_(address))).first;
    auto& [current_block, current_successors] = *current_it;

    // Iterate over successor addresses
    for (auto const& next_address : current_block.get_next_addresses())
    {
        // Ambiguous jump?
        if (!next_address)
        {
            // TODO

            continue;
        }

        // Search for an existing block already covering the next address
        auto const existing_block_search = lower_bound(*next_address);

        // No block found?
        if (existing_block_search == upper_bound(*next_address))
        {
            // RECURSE with this successor
            current_successors.insert(construct(*next_address).first);

            continue;
        }

        // Inquire the search result
        auto& [existing_block, existing_successors] = *existing_block_search;

        // Search for the respective instruction in the found block
        auto const instruction_search = existing_block.find(*next_address);

        // ASSERT a found instruction
        if (instruction_search == existing_block.end())
            throw std::logic_error("Overlapping instructions");

        // Is it the first instruction?
        if (instruction_search == existing_block.begin())
        {
            // Use the found block as a successor
            current_successors.insert(existing_block);

            continue;
        }

        // Dissect the found block
        control_flow_block new_block(instruction_search, existing_block.end());
        auto existing_node = extract(existing_block_search);
        existing_node.key().erase(instruction_search, existing_block.end());
        insert(std::move(existing_node));

        // Record the new block
        auto& [next_block, next_successors] = *try_emplace(std::move(new_block)).first;

        // Update successors
        current_successors.insert(next_block);
        next_successors = existing_successors;
        existing_successors = { next_block };
    }

    return *current_it;
}
