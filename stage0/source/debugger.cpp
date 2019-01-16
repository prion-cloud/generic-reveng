#include <algorithm>

#include "debugger.hpp"

debugger::debugger(executable const& executable)
    : disassembler_(executable.architecture), emulator_(executable.architecture)
{
    int sp_register;
    int bp_register;

    switch (executable.architecture)
    {
    case machine_architecture::x86_32:
        ip_register_ = UC_X86_REG_EIP;
        sp_register = UC_X86_REG_ESP;
        bp_register = UC_X86_REG_EBP;
        break;
    case machine_architecture::x86_64:
        ip_register_ = UC_X86_REG_RIP;
        sp_register = UC_X86_REG_RSP;
        bp_register = UC_X86_REG_RBP;
        break;
    default:
        throw std::runtime_error("Unsupported architecture");
    }

    for (auto const& [address, data] : executable.sections)
    {
        if (data.empty())
            continue;

        emulator_.allocate_memory(address, data.size());
        emulator_.write_memory(address, data);
    }

    position(executable.entry_point);

    cfg_root_ = construct_cfg();

    position(executable.entry_point);

    auto constexpr stack_bottom = UINT32_MAX;
    auto constexpr stack_size = 0x1000;
    emulator_.allocate_memory(stack_bottom - stack_size + 1, stack_size);

    emulator_.write_register(sp_register, stack_bottom);
    emulator_.write_register(bp_register, stack_bottom);
}

uint64_t debugger::position() const
{
    return emulator_.read_register(ip_register_);
}
void debugger::position(uint64_t const address)
{
    emulator_.write_register(ip_register_, address);
}

std::shared_ptr<instruction> debugger::current_instruction() const
{
    auto address = position();
    auto code = emulator_.read_memory(address, std::size(instruction().bytes));

    return disassembler_(&code, &address);
}

control_flow_graph const& debugger::cfg() const
{
    return cfg_;
}
control_flow_graph::value_type const& debugger::cfg_root() const
{
    return *cfg_root_;
}

control_flow_graph::const_iterator debugger::construct_cfg()
{
    // Record the new block
    std::vector<std::optional<uint64_t>> next_addresses;
    auto const current = cfg_.try_emplace(create_block(&next_addresses)).first;
    auto& current_successors = current->second;

    // Iterate over successor addresses
    for (auto const& next_address : next_addresses)
    {
        // Ambiguous jump?
        if (!next_address)
        {
            // TODO
            continue;
        }

        // Search for an existing block already covering the next address
        auto const existing_block_search = cfg_.lower_bound(*next_address);

        // No block found?
        if (existing_block_search == cfg_.upper_bound(*next_address))
        {
            // RECURSE with this successor
            position(*next_address);
            current_successors.insert(&construct_cfg()->first);

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
            current_successors.insert(&existing_block);

            continue;
        }

        // Dissect the found block
        control_flow_block new_block(instruction_search, existing_block.end());
        auto existing_node = cfg_.extract(existing_block_search);
        existing_node.key().erase(instruction_search, existing_block.end());
        cfg_.insert(std::move(existing_node));

        // Record the new block
        auto& [next_block, next_successors] = *cfg_.try_emplace(std::move(new_block)).first;

        // Update successors
        current_successors.insert(&next_block);
        next_successors = existing_successors;
        existing_successors = { &next_block };
    }

    return current;
}

control_flow_block debugger::create_block(std::vector<std::optional<uint64_t>>* next_addresses)
{
    // Create a new block
    control_flow_block block;

    // Fill the block with contiguous instructions
    while (true)
    {
        // Store current machine instruction
        auto const instruction = current_instruction();
        block.insert(block.end(), instruction);

        // Inquire successors
        *next_addresses = get_next_addresses(instruction);

        // Interrupt the block creation if...
        if (next_addresses->empty() ||                    // - there are no successors or
            !std::all_of(                                 // - some (actual) jumps or
                next_addresses->begin(), next_addresses->end(),
                [&instruction](auto const& address)
                {
                    return address &&
                        *address == instruction->address + instruction->size;
                }) ||
            cfg_.lower_bound(*next_addresses->front()) != // - the next instruction is known
                cfg_.upper_bound(*next_addresses->front()))
            break;

        // Continue the block creation
        position(*next_addresses->front());
    }

    return block;
}

std::vector<std::optional<uint64_t>> debugger::get_next_addresses(std::shared_ptr<instruction> const& instruction)
{
    if (instruction->detail == nullptr)
        throw std::runtime_error("Missing instruction detail");

    // TODO only x86?

    auto const op0 = instruction->detail->x86.operands[0];

    std::vector<std::optional<uint64_t>> successors;

    switch (instruction->id)
    {
    case X86_INS_INVALID:
    case X86_INS_INT3:
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
        successors.emplace_back(instruction->address + instruction->size);
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
        successors.emplace_back(instruction->address + instruction->size);
        break;
    }

    return successors;
}
