#include "stdafx.h"

#include "deobfuscator.h"

obfuscation_graph_x86::node::node(const std::shared_ptr<debugger> debugger, const uint64_t address,
    std::map<uint64_t, node*> previous_nodes, const uint64_t stop, bool last_error)
{
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
        break;
    default:
        nexts.push_back(debugger->next_instruction()->address);
    }

    previous_nodes.emplace(address, this);

    for (const auto next : nexts)
    {
        if (next == stop)
        {
            std::cout << "Stop" << std::endl;
            continue;
        }

        if (previous_nodes.find(next) == previous_nodes.end())
        {
            next_.push_back(std::make_shared<node>(debugger, next, previous_nodes, stop, last_error));
            continue;
        }
        
        std::cout << "Loop" << std::endl;
        next_.push_back(std::shared_ptr<node>(previous_nodes.at(next)));
    }
}

obfuscation_graph_x86::obfuscation_graph_x86(const node root)
    : root_(root) { }

obfuscation_graph_x86 obfuscation_graph_x86::build(const std::shared_ptr<debugger> debugger, const uint64_t root_address, const uint64_t stop)
{
    return obfuscation_graph_x86(node(debugger, root_address, { }, stop, false));
}

deobfuscator_x86::deobfuscator_x86(loader& loader, std::vector<uint8_t> code)
    : debugger_(std::make_shared<debugger>(loader, code)) { }

void deobfuscator_x86::build(const uint64_t start, const uint64_t stop) const
{
    const auto graph = obfuscation_graph_x86::build(debugger_, start, stop);

}
