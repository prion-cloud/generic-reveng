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

static void log_event(const std::string& name, const traceback_x86& traceback, const bool full, const uint16_t color)
{
    std::cout << "[" << colorize(color) << name << decolorize << "] " << std::hex << std::uppercase << traceback->address;

    if (full)
        std::cout << " " << traceback->str_mnemonic << " " << traceback->str_operands;

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

    build(debugger, root_address, assemble_x86(0, "pop " + root_instruction.str_operands));

    debugger->reset(snapshot);

    std::cout << "(" << std::dec << node_map_.size() << ")" << std::endl;
}

traceback_x86 control_flow_graph_x86::find_traceback(const uint64_t address) const
{
    return node_map_.at(address)->traceback;
}

control_flow_graph_x86::node* control_flow_graph_x86::build(const std::shared_ptr<debugger> debugger, const uint64_t address, const std::vector<uint8_t> stop)
{
    const auto cur = new node;

    debugger->jump_to(address);
    cur->traceback = debugger->step_into();

    node_map_.emplace(address, cur);

    if (cur->traceback.has_failed())
        log_event("FAIL", cur->traceback, true, FOREGROUND_RED | FOREGROUND_INTENSITY);

    if (cur->traceback->code == stop)
    {
        log_event("STOP", cur->traceback, false, FOREGROUND_GREEN);
        return cur;
    }

    std::vector<uint64_t> next_addresses;
    emulation_snapshot snapshot { };
    if (cur->traceback->type == instruction_type::jump && cur->traceback->is_conditional)
    {
        log_event("FORK", cur->traceback, false, FOREGROUND_YELLOW);
        next_addresses.push_back(address + cur->traceback->code.size());
        next_addresses.push_back(cur->traceback->operands.at(0).imm);

        snapshot = debugger->take_snapshot();
    }
    else next_addresses.push_back(debugger->next_instruction().address);

    for (auto i = 0; i < next_addresses.size(); ++i)
    {
        const auto next_address = next_addresses.at(i);

        node* next;
        if (node_map_.find(next_address) == node_map_.end())
        {
            if (i > 0)
                debugger->reset(snapshot);

            next = build(debugger, next_address, stop);
        }
        else
        {
            log_event("LOOP", cur->traceback, false, FOREGROUND_CYAN);
            next = node_map_.at(next_address);
        }

        cur->next.push_back(next);
        next->previous.push_back(cur);
    }

    return cur;
}
