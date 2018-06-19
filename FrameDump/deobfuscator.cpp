#include "stdafx.h"

#include <iomanip>

#include "deobfuscator.h"

static bool verbose = false;

obfuscation_graph_x86::node::node(const std::shared_ptr<debugger> debugger, const uint64_t address, const std::pair<std::string, std::string> stop,
    std::map<uint64_t, node*>& nodes, uint64_t& stop_address, bool last_error)
{
    nodes.emplace(address, this);

    if (verbose)
        std::cout << std::hex << std::uppercase << address << std::endl;

    debugger->jump_to(address);
    instruction_ = debugger->next_instruction();

    if (instruction_->mnemonic == stop.first && instruction_->operands == stop.second)
    {
        if (verbose)
            std::cout << "Stop" << std::endl;

        stop_address = instruction_->address;
        return;
    }

    if (debugger->step_into().error != UC_ERR_OK)
    {
        if (last_error)
        {
            std::cout << "Fatal: " << std::hex << std::uppercase << address << std::endl;
            return;
        }

        if (verbose)
            std::cout << "Error" << std::endl;

        last_error = true;
    }
    else last_error = false;

    std::vector<uint64_t> next_addresses;

    stack_representation stack { };
    switch (instruction_->id)
    {
    case X86_INS_JO:
    case X86_INS_JNO:
    case X86_INS_JS:
    case X86_INS_JNS:
    case X86_INS_JE:
    case X86_INS_JNE:
    case X86_INS_JB:
    case X86_INS_JAE:
    case X86_INS_JBE:
    case X86_INS_JA:
    case X86_INS_JL:
    case X86_INS_JGE:
    case X86_INS_JLE:
    case X86_INS_JG:
    case X86_INS_JP:
    case X86_INS_JNP:
    case X86_INS_JCXZ:
        if (verbose)
            std::cout << "Jump" << std::endl;
        next_addresses.push_back(address + instruction_->bytes.size());
        next_addresses.push_back(instruction_->jump.value());
        stack = debugger->get_stack();
        break;
    default:
        next_addresses.push_back(debugger->next_instruction()->address);
    }

    for (auto i = 0; i < next_addresses.size(); ++i)
    {
        const auto next_address = next_addresses.at(i);

        if (i > 0)
            debugger->set_stack(stack);

        if (nodes.find(next_address) == nodes.end())
        {
            next_.push_back(new node(debugger, next_address, stop, nodes, stop_address, last_error));
            continue;
        }

        if (verbose)
            std::cout << "Loop: " << std::hex << std::uppercase << next_address << std::endl;
        next_.push_back(nodes.at(next_address));
    }
}

obfuscation_graph_x86::obfuscation_graph_x86(const std::shared_ptr<debugger> debugger, const uint64_t root_address)
    : root_address_(root_address)
{
    const auto width = sizeof(uint64_t) * 2;
    const std::string title = "Obfuscation ";

    std::cout << title << std::right << std::setw(width)
              << std::hex << std::uppercase << root_address << std::endl;

    const auto root_instruction = debugger->disassemble_at(root_address);
    if (root_instruction->mnemonic != "push")
    {
        std::cout << "Unexpected root" << std::endl;
        return;
    }

    const auto stack = debugger->get_stack();

    std::map<uint64_t, node*> nodes;

    root_ = node(debugger, root_address, std::make_pair("pop", root_instruction->operands), nodes, stop_address_);

    debugger->set_stack(stack);

    std::cout << std::string(title.size(), ' ') << std::right << std::setw(width)
              << std::hex << std::uppercase << stop_address_
              << " (" << std::dec << nodes.size() << ")" << std::endl;
}

deobfuscator_x86::deobfuscator_x86(loader& loader, std::vector<uint8_t> code)
    : debugger_(std::make_shared<debugger>(loader, code)) { }

std::vector<obfuscation_graph_x86> deobfuscator_x86::inspect_framed(const std::vector<uint64_t> addresses) const
{
    std::vector<obfuscation_graph_x86> graphs;
    for (auto i = 0; i < addresses.size(); ++i)
    {
        std::cout << std::dec << i + 1 << ":" << std::endl;
        graphs.push_back(obfuscation_graph_x86(debugger_, addresses.at(i)));
        std::cout << std::endl;
    }

    return graphs;
}
