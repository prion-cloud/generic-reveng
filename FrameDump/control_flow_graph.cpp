#include "stdafx.h"

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

control_flow_graph_x86::control_flow_graph_x86(const std::shared_ptr<debugger>& debugger, const uint64_t root_address)
{
    const auto root_instruction = debugger->disassemble_at(root_address);
    if (root_instruction.str_mnemonic != "push")
    {
        std::cout << "Unexpected root" << std::endl;

        root_ = nullptr;
        return;
    }

    root_ = build(debugger, root_address, assemble_x86(0, "pop " + root_instruction.str_operands), map_);
}

void control_flow_graph_x86::draw() const
{
    std::set<block> blocks;
    for (const auto m : map_)
        blocks.insert(*m.second.first);

    auto id = 'A';
    for (const auto& block : blocks)
    {
        const auto last = block.instructions.back();
        const auto last_string = last.to_string(last.is_conditional || last.is_volatile);

        const auto width = last_string.size();

        std::cout << id << std::setfill('-') << std::setw(width + 2) << std::left << "(" + std::to_string(block.instructions.size()) + ")" << '+' << std::endl;

        std::cout << std::setfill(' ');

        if (block.instructions.size() > 1)
            std::cout << "| " << std::setw(width) << std::left << block.instructions.front().to_string(false) << " |" << std::endl;
        if (block.instructions.size() > 2)
            std::cout << "| " << std::setw(width) << std::left << ':' << " |" << std::endl;
        std::cout << "| " << std::setw(width) << std::left << last_string << " |" << std::endl;

        std::cout << '+' << std::string(width + 2, '-') << '+' << std::endl;

        for (const auto n : block.next)
            std::cout << "-> " << n->instructions.front().to_string(false) << std::endl;

        std::cout << std::endl;

        ++id;
    }
}

control_flow_graph_x86::block* control_flow_graph_x86::build(const std::shared_ptr<debugger>& debugger, uint64_t address,
    const std::vector<uint8_t>& stop, std::map<uint64_t, std::pair<block*, size_t>>& map)
{
    const auto cur = new block;

    const std::function<block*(uint64_t)> split_existing = [cur, &map](const uint64_t next_address)
    {
        const auto [orig, index] = map.at(next_address);

        if (index > 0)
        {
            const auto begin = orig->instructions.begin() + index;
            const auto end = orig->instructions.end();

            const auto next = new block;
            next->instructions = std::vector<instruction_x86>(begin, end);
            next->next = orig->next;

            for (auto j = 0; j < end - begin; ++j)
                map[(begin + j)->address] = std::make_pair(next, j);

            orig->instructions.erase(begin, end);

            if (orig == cur)
                next->next.push_back(next);
            else orig->next = { next };

            return next;
        }

        return orig;
    };

    do
    {
        map.emplace(address, std::make_pair(cur, cur->instructions.size()));

        debugger->jump_to(address);

        const auto instruction = debugger->next_instruction();
        cur->instructions.push_back(instruction);

        if (debugger->step_into() != UC_ERR_OK)
            std::cout << "FAIL: " << instruction.to_string(true) << std::endl;

        if (instruction.code == stop)
            break;

        std::vector<uint64_t> next_addresses;
        emulation_snapshot snapshot;
        if (instruction.type == ins_jump && instruction.is_conditional)
        {
            next_addresses.push_back(address + instruction.code.size());
            next_addresses.push_back(std::get<op_immediate>(instruction.operands.at(0).value));

            snapshot = debugger->take_snapshot();
        }
        else
        {
            const auto next_address = debugger->next_instruction().address;

            if (map.find(next_address) == map.end())
            {
                address = next_address;
                continue;
            }

            cur->next.push_back(split_existing(next_address));
            break;
        }

        for (const auto next_address : next_addresses)
        {
            cur->next.push_back(map.find(next_address) == map.end()
                ? build(debugger, next_address, stop, map)
                : split_existing(next_address));

            debugger->reset(snapshot);
        }

        break;
    }
    while (true);

    return cur;
}

bool operator<(const control_flow_graph_x86::block& block1, const control_flow_graph_x86::block& block2)
{
    return block1.instructions.front().address < block2.instructions.front().address;
}
