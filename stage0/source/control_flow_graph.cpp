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

std::unordered_set<std::optional<uint64_t>> get_called_addresses(instruction const& instruction)
{
    // TODO only x86?

    auto const op0 = instruction.detail->x86.operands[0];

    std::unordered_set<std::optional<uint64_t>> called_addresses;

    switch (instruction.id)
    {
    case X86_INS_CALL:
        switch (op0.type)
        {
        case X86_OP_IMM:
            called_addresses.emplace(op0.imm);
            break;
        default:
            called_addresses.emplace(std::nullopt);
            break;
        }
        break;
    }

    return called_addresses;
}
std::unordered_set<std::optional<uint64_t>> get_jumped_addresses(instruction const& instruction)
{
    // TODO only x86?

    auto const op0 = instruction.detail->x86.operands[0];

    std::unordered_set<std::optional<uint64_t>> jumped_addresses;

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
        jumped_addresses.emplace(instruction.address + instruction.size);
    case X86_INS_JMP:
        switch (op0.type)
        {
        case X86_OP_IMM:
            jumped_addresses.emplace(op0.imm);
            break;
        default:
            jumped_addresses.emplace(std::nullopt);
            break;
        }
        break;
    default:
        jumped_addresses.emplace(instruction.address + instruction.size);
        break;
    }

    return jumped_addresses;
}

control_flow_block::control_flow_block(disassembler const& disassembler, uint64_t address,
    std::optional<uint64_t> const& max_address, std::basic_string_view<uint8_t> code)
{
    // Fill the block with contiguous instructions
    do
    {
        // Disassemble instruction
        auto instruction = disassembler(&address, &code);

        // Inquire calls and jumps
        called_addresses_.merge(get_called_addresses(*instruction));
        jumped_addresses_ = get_jumped_addresses(*instruction);

        // Store instruction
        insert(end(), std::move(instruction));
    }
    while (
        // Uniqueness
        jumped_addresses_.size() == 1 &&
        // Unambiguity
        *jumped_addresses_.begin() &&
        // Unintermediateness
        *jumped_addresses_.begin() == (*crbegin())->address + (*crbegin())->size &&
        // Size integrity
        (!max_address || *jumped_addresses_.begin() < max_address));
}

std::unordered_set<std::optional<uint64_t>> const& control_flow_block::called_addresses() const
{
    return called_addresses_;
}
std::unordered_set<std::optional<uint64_t>> const& control_flow_block::jumped_addresses() const
{
    return jumped_addresses_;
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

control_flow_graph::control_flow_graph(disassembler const& disassembler,
    std::function<std::basic_string_view<uint8_t>(uint64_t)> const& GET_MEMORY, uint64_t const address)
{
    root_ = construct(disassembler, GET_MEMORY, address);
}

control_flow_graph::node const& control_flow_graph::root() const
{
    return *root_;
}

std::unordered_set<std::optional<uint64_t>> const& control_flow_graph::called_addresses() const
{
    return called_addresses_;
}

control_flow_graph::iterator control_flow_graph::construct(disassembler const& disassembler,
    std::function<std::basic_string_view<uint8_t>(uint64_t)> const& GET_MEMORY, uint64_t const address)
{
    // Use the start address of the next higher block as a maximum
    std::optional<uint64_t> max_address;
    auto const higher_block_search = lower_bound(address);
    if (higher_block_search != end())
        max_address = (*higher_block_search->first.begin())->address;

    // Create a new block
    auto const current_it = try_emplace(control_flow_block(disassembler, address, max_address, GET_MEMORY(address))).first;
    auto const& current_block = current_it->first;

    called_addresses_.insert(
        current_block.called_addresses().begin(),
        current_block.called_addresses().end());

    // Iterate over successor addresses
    auto* current_successors = &current_it->second;
    for (auto const& next_address : current_block.jumped_addresses())
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
            current_successors->insert(construct(disassembler, GET_MEMORY, *next_address)->first);

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
            current_successors->insert(existing_block);

            continue;
        }

        control_flow_block new_block(instruction_search, existing_block.end());

        // Dissect the found block
        auto existing_node = extract(existing_block_search);
        existing_node.key().erase(instruction_search, existing_block.end());
        insert(std::move(existing_node));

        // Record the new block
        auto& [next_block, next_successors] = *try_emplace(std::move(new_block)).first;

        // Update successors
        current_successors->insert(next_block);
        next_successors = existing_successors;
        existing_successors = { next_block };

        // React to self-dissection
        if (&existing_block == &current_block)
            current_successors = &next_successors;
    }

    return current_it;
}
