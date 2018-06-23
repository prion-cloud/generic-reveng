#include "stdafx.h"

#include "console.h"
#include "control_flow_graph.h"

static std::vector<uint8_t> assemble_x86(const uint64_t address, const std::string string)
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

static void log_occurence(const uint16_t color, const unsigned basic_block_id, const std::string name, const traceback_x86& traceback, const bool instruction)
{
    std::cout << basic_block_id << "[" << colorize(color) << name << decolorize << "] " << std::hex << std::uppercase << traceback->address;

    if (instruction)
        std::cout << " " << traceback->str_mnemonic << " " << traceback->str_operands;

    std::cout << std::endl;
}

control_flow_graph_x86::node::node(const std::shared_ptr<debugger> debugger, const uint64_t address, const std::vector<uint8_t> stop,
    std::map<uint64_t, node*>& node_map, memory_monitor& monitor, uint64_t& stop_address)
{
    node_map.emplace(address, this);

    debugger->jump_to(address);
    traceback = debugger->step_into();

    monitor.inspect_access(traceback);

    if (traceback.has_failed())
        log_occurence(FOREGROUND_RED | FOREGROUND_INTENSITY, 0, "FAIL", traceback, true);

    if (traceback->code == stop)
    {
        log_occurence(FOREGROUND_GREEN, 0, "STOP", traceback, false);
        stop_address = traceback->address;
        return;
    }

    std::vector<uint64_t> next_addresses;
    emulation_snapshot snapshot { };
    if (traceback->type == instruction_type::jump && traceback->is_conditional)
    {
        log_occurence(FOREGROUND_YELLOW, 0, "FORK", traceback, false);
        next_addresses.push_back(address + traceback->code.size());
        next_addresses.push_back(traceback->operands.at(0).imm);

        snapshot = debugger->take_snapshot();
    }
    else next_addresses.push_back(debugger->next_instruction().address);

    for (auto i = 0; i < next_addresses.size(); ++i)
    {
        const auto next_address = next_addresses.at(i);

        node* next_node;
        if (node_map.find(next_address) == node_map.end())
        {
            if (i > 0)
                debugger->reset(snapshot);

            next_node = new node(debugger, next_address, stop, node_map, monitor, stop_address);
        }
        else
        {
            log_occurence(FOREGROUND_CYAN, 0, "LOOP", traceback, false);
            next_node = node_map.at(next_address);
        }

        next_node->previous.push_back(this);
        next.push_back(next_node);
    }
}

control_flow_graph_x86::control_flow_graph_x86(const std::shared_ptr<debugger> debugger, const uint64_t root_address)
    : root_address_(root_address)
{
    std::cout << std::hex << std::uppercase << root_address << std::endl;

    const auto root_instruction = debugger->disassemble_at(root_address);
    if (root_instruction.str_mnemonic != "push")
    {
        std::cout << "Unexpected root" << std::endl;
        return;
    }

    const auto snapshot = debugger->take_snapshot();

    root_ = node(debugger, root_address, assemble_x86(0, "pop " + root_instruction.str_operands),
        node_map_, monitor_, stop_address_);

    debugger->reset(snapshot);

    std::cout << "(" << std::dec << node_map_.size() << ")" << std::endl;
}

traceback_x86 control_flow_graph_x86::find_traceback(const uint64_t address) const
{
    return node_map_.at(address)->traceback;
}
