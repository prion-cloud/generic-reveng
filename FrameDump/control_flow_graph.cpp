#include "stdafx.h"

#include "control_flow_graph.h"
#include "display.h"

#define CHAR_ID '*'
#define CHAR_PREV '#'
#define CHAR_NEXT '~'

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
static void replace_first(std::string& string, const char old_char, const char new_char)
{
    const auto pos = string.find_first_of(old_char);

    if (pos == std::string::npos)
        return;

    string = string.substr(0, pos) + new_char + string.substr(pos + 1);
}

std::string control_flow_graph_x86::block::to_string() const
{
    const std::string l = "| ";
    const std::string r = " |";

    const auto h = '-';

    const auto eu = '.';
    const auto ed = '\'';

    std::ostringstream ss;

    const auto last = instructions.back();
    const auto last_string = last.to_string(last.is_conditional || last.is_volatile);

    const auto width = last_string.size();

    const auto padding = 1;

    ss << std::string(padding, ' ') << CHAR_ID << std::setfill(h) << std::setw(width + l.size() + r.size() - 2) << std::left << "(" + std::to_string(instructions.size()) + ")" << eu;
    for (unsigned i = 0; i < previous.size(); ++i)
        ss << ' ' << CHAR_PREV;
    ss << std::endl;

    ss << std::setfill(' ');

    if (instructions.size() > 1)
        ss << std::string(padding, ' ') << l << std::setw(width) << std::left << instructions.front().to_string(false) << r << std::endl;
    if (instructions.size() > 2)
        ss << std::string(padding, ' ') << l << std::setw(width) << std::left << ':' << r << std::endl;
    ss << std::string(padding, ' ') << l << std::setw(width) << std::left << last_string << r << std::endl;

    ss << std::string(padding, ' ') << ed << std::string(width + 2, '-') << ed;
    for (unsigned i = 0; i < next.size(); ++i)
        ss << ' ' << CHAR_NEXT;
    ss << std::endl << std::endl;

    return ss.str();
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
    std::map<block, char> map1;
    std::map<char, block> map2;

    auto id = 'A';
    for (const auto m : map_)
    {
        const auto [it, b] = map1.try_emplace(*m.second.first, id);
        if (b)
            map2.emplace(id++, *m.second.first);
    }

    for (const auto& [block_id, block] : map2)
    {
        const auto no_pred = block.previous.empty();
        const auto no_succ = block.next.empty();

        if (no_pred ^ no_succ)
        {
            std::cout << dsp::colorize(FOREGROUND_INTENSITY |
                (no_pred ? FOREGROUND_GREEN : FOREGROUND_RED));
        }

        auto block_string = block.to_string();

        replace_first(block_string, CHAR_ID, block_id);

        for (const auto p : block.previous)
            replace_first(block_string, CHAR_PREV, map1.at(*p));
        for (const auto n : block.next)
            replace_first(block_string, CHAR_NEXT, map1.at(*n));

        std::cout << block_string << dsp::decolorize;
    }
}

control_flow_graph_x86::block* control_flow_graph_x86::build(const std::shared_ptr<debugger>& debugger, uint64_t address,
    const std::vector<uint8_t>& stop, std::map<uint64_t, std::pair<block*, size_t>>& map)
{
    // New (current) block
    const auto cur = new block;

    // Appends an existing block at the specified address as successor
    const std::function<bool(uint64_t)> success = [cur, &map](const uint64_t next_address)
    {
        const auto map_it = map.find(next_address);
        if (map_it == map.end())
        {
            // No block exists at this address
            return false;
        }

        const auto [orig, index] = map_it->second;

        if (index == 0)
        {
            // Block does not have to be split
            orig->previous.insert(cur);
            cur->next.insert(orig);
            return true;
        }

        const auto begin = orig->instructions.begin() + index;
        const auto end = orig->instructions.end();

        const auto next = new block;

        // Copy tail
        next->instructions = std::vector<instruction_x86>(begin, end);

        // Update map
        // TODO: Inefficient with large blocks
        for (auto j = 0; j < end - begin; ++j)
            map[(begin + j)->address] = std::make_pair(next, j);

        // Truncate tail
        orig->instructions.erase(begin, end);

        // Update successor information
        cur->next.insert(next);
        next->next = orig->next;
        orig->next = { next };

        // Update predecessor information
        next->previous.insert(orig);
        for (const auto nn : next->next)
        {
            nn->previous.erase(orig);
            nn->previous.insert(next);
        }
        next->previous.insert(cur);

        return true;
    };

    // Repeat until successors are set
    while (cur->next.empty())
    {
        // Map address to block and index
        map.emplace(address, std::make_pair(cur, cur->instructions.size()));

        debugger->jump_to(address);

        const auto instruction = debugger->next_instruction();

        // Append instruction
        cur->instructions.push_back(instruction);

        // Emulate instruction
        if (debugger->step_into() != UC_ERR_OK)
            std::cout << "FAIL: " << instruction.to_string(true) << std::endl;

        if (instruction.code == stop)
        {
            // Reached final instruction, stop without successor
            break;
        }

        if (instruction.type == ins_jump && instruction.is_conditional)
        {
            std::vector<uint64_t> next_addresses;

            // Consider both jump results
            next_addresses.push_back(address + instruction.code.size());
            next_addresses.push_back(std::get<op_immediate>(instruction.operands.at(0).value));

            // Save current emulation state
            const auto snapshot = debugger->take_snapshot();

            for (const auto next_address : next_addresses)
            {
                if (!success(next_address))
                {
                    // Recursively create a new successor
                    const auto next = build(debugger, next_address, stop, map);
                    next->previous.insert(cur);
                    cur->next.insert(next);
                }

                // Reset to original state
                debugger->reset(snapshot);
            }
        }
/*
        else if (instruction.is_volatile) // TODO
        {
            const auto next_address = debugger->next_instruction().address;

            if (!success(next_address))
            {
                const auto next = build(debugger, next_address, stop, map);
                next->previous.insert(cur);
                cur->next.insert(next);
            }
        }
*/
        else
        {
            const auto next_address = debugger->next_instruction().address;

            if (!success(next_address))
            {
                // Advanced address and continue
                address = next_address;
            }
        }
    }

    return cur;
}

bool operator<(const control_flow_graph_x86::block& block1, const control_flow_graph_x86::block& block2)
{
    return block1.instructions.front().address < block2.instructions.front().address;
}
