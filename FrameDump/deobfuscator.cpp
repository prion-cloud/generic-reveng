#include "stdafx.h"

#include "deobfuscator.h"

static uint64_t counter;

obfuscation_graph_x86::node::node(const std::shared_ptr<debugger> debugger, const uint64_t address, const uint64_t stop_address,
    std::map<uint64_t, node*>& nodes, bool last_error)
{
    ++counter;

    std::cout << std::hex << std::uppercase << address << std::endl;

    debugger->jump_to(address);

    instruction_ = debugger->next_instruction();
    if (debugger->step_into().error != UC_ERR_OK)
    {
        if (last_error)
        {
            std::cout << "Error2" << std::endl;
            return;
        }

        std::cout << "Error1" << std::endl;

        last_error = true;
    }
    else last_error = false;

    std::vector<uint64_t> nexts;

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
        std::cout << "Jump" << std::endl;
        nexts.push_back(address + instruction_->bytes.size());
        nexts.push_back(instruction_->jump.value());
        stack = debugger->get_stack();
        break;
    default:
        nexts.push_back(debugger->next_instruction()->address);
    }

    nodes.emplace(address, this);

    for (auto i = 0; i < nexts.size(); ++i)
    {
        const auto next = nexts.at(i);

        if (next == stop_address)
        {
            std::cout << "Stop" << std::endl;
            continue;
        }

        if (i > 0)
            debugger->set_stack(stack);

        if (nodes.find(next) == nodes.end())
        {
            next_.push_back(std::make_shared<node>(debugger, next, stop_address, nodes, last_error));
            continue;
        }

        std::cout << "Loop: " << std::hex << std::uppercase << next << std::endl;
        next_.push_back(std::shared_ptr<node>(nodes.at(next)));
    }
}

obfuscation_graph_x86::obfuscation_graph_x86(const node root)
    : root_(root) { }

obfuscation_graph_x86 obfuscation_graph_x86::build(const std::shared_ptr<debugger> debugger, const uint64_t root_address, const uint64_t stop_address)
{
    counter = 0;

    std::map<uint64_t, node*> nodes;
    return obfuscation_graph_x86(node(debugger, root_address, stop_address, nodes, false));
}

deobfuscator_x86::deobfuscator_x86(loader& loader, std::vector<uint8_t> code)
    : debugger_(std::make_shared<debugger>(loader, code)) { }

void deobfuscator_x86::build(const uint64_t start, const uint64_t stop) const
{
    const auto graph = obfuscation_graph_x86::build(debugger_, start, stop);

}
