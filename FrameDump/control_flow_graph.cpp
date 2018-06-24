#include "stdafx.h"

#include "console.h"
#include "control_flow_graph.h"

static std::vector<uint8_t> assemble_x86(const uint64_t address, const std::string& string)
{
    const std::string var_code = "v1";
    const std::string var_length = "v2";

    auto s_python =
        "from keystone import *\n"
        "ks = Ks(KS_ARCH_X86, KS_MODE_64)\n"
        + var_code + ", count = ks.asm(b\"" + string + "\", " + std::to_string(address) + ")\n"
        + var_length + " = len(" + var_code + ")";

    Py_Initialize();
    PyRun_SimpleString(s_python.c_str());

    const auto main = PyImport_AddModule("__main__");

    const auto p_code = PyObject_GetAttrString(main, var_code.c_str());
    const auto length = _PyInt_AsInt(PyObject_GetAttrString(main, var_length.c_str()));
    
    std::vector<uint8_t> code;
    for (auto i = 0; i < length; ++i)
        code.push_back(_PyInt_AsInt(PyList_GetItem(p_code, i)));

    Py_Finalize();

    return code;
}

static void log_event(const std::string& name, const instruction_x86& instruction, const bool full, const uint16_t color = FOREGROUND_WHITE)
{
    std::cout << "[" << colorize(color) << name << decolorize << "] " << std::hex << std::uppercase << instruction.address;

    if (full)
        std::cout << " " << instruction.str_mnemonic << " " << instruction.str_operands;

    std::cout << std::endl;
}

control_flow_graph_x86::control_flow_graph_x86(const std::shared_ptr<debugger>& debugger, const uint64_t root_address)
{
    const auto root_instruction = debugger->disassemble_at(root_address);
    if (root_instruction.str_mnemonic != "push")
    {
        std::cout << "Unexpected root" << std::endl;
        return;
    }

    const auto snapshot = debugger->take_snapshot();

    root_ = build(debugger, root_address, assemble_x86(0, "pop " + root_instruction.str_operands), node_map_, paths_);

    debugger->reset(snapshot);

    std::cout << "(" << std::dec << node_map_.size() << ")" << std::endl;
}

control_flow_graph_x86::node* control_flow_graph_x86::build(const std::shared_ptr<debugger>& debugger, const uint64_t address, const std::vector<uint8_t> stop,
    std::map<uint64_t, node*>& node_map, std::set<path>& paths)
{
    const auto cur = new node;
    node_map.emplace(address, cur);

    debugger->jump_to(address);
    cur->instruction = debugger->next_instruction();

    if (debugger->step_into() != UC_ERR_OK)
        log_event("FAIL", cur->instruction, true, FOREGROUND_RED | FOREGROUND_INTENSITY);

    if (cur->instruction.code == stop)
    {
        log_event("STOP", cur->instruction, false, FOREGROUND_GREEN);
        return cur;
    }

    std::vector<uint64_t> next_addresses;
    emulation_snapshot snapshot { };
    if (cur->instruction.type == ins_jump && cur->instruction.is_conditional)
    {
        log_event("FORK", cur->instruction, false, FOREGROUND_YELLOW);
        next_addresses.push_back(address + cur->instruction.code.size());
        next_addresses.push_back(std::get<op_immediate>(cur->instruction.operands.at(0).value));

        snapshot = debugger->take_snapshot();
    }
    else next_addresses.push_back(debugger->next_instruction().address);

    if (cur->instruction.is_volatile)
        log_event("VOLA", cur->instruction, true);

    for (unsigned i = 0; i < next_addresses.size(); ++i)
    {
        const auto next_address = next_addresses.at(i);

        node* next;
        if (node_map.find(next_address) == node_map.end())
        {
            if (i > 0)
                debugger->reset(snapshot);

            next = build(debugger, next_address, stop, node_map, paths);
        }
        else
        {
            log_event("LOOP", cur->traceback, false, FOREGROUND_CYAN);
            next = node_map.at(next_address);
        }

        cur->next.push_back(next);
        next->previous.push_back(cur);
    }

    return cur;
}
