#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include "../include/scout/cfg.h"
#include "../include/scout/debugger.h"
#include "../include/scout/utf8_canvas.h"

utf8_char const h("\u2500"/* │ */);
utf8_char const v("\u2502"/* ─ */);

utf8_char const dr("\u250C"/* ┌ */);
utf8_char const dl("\u2510"/* ┐ */);
utf8_char const ur("\u2514"/* └ */);
utf8_char const ul("\u2518"/* ┘ */);

utf8_char const dh("\u252C"/* ┬ */);
utf8_char const uh("\u2534"/* ┴ */);

std::string get_instruction_string(machine_instruction const& instruction)
{
    /* TODO \x1B[38;2;<r>;<g>;<b>;48;2;<r>;<g>;<b>m<text> */

    std::ostringstream oss_instruction;
    oss_instruction << std::hex << instruction.address;

    auto const disassembly = instruction.disassemble();

    oss_instruction << ' ' << disassembly->mnemonic;

    std::string const operands_string = disassembly->op_str;
    if (operands_string.size() > 0)
    {
        oss_instruction << ' ' << std::regex_replace(
            operands_string,
            std::regex("(0x)([\\dabcdef]*)"), "$2");
    }

    return oss_instruction.str();
}

void print_cfg(cfg const& cfg)
{
    auto constexpr width = 120;
    auto constexpr block_margin_size = 1;

    utf8_canvas canvas(width);

    std::unordered_map<cfg::block const*, std::shared_ptr<utf8_text_rectangle>> canvas_blocks;

    auto const cfg_layout = cfg.get_layout();

    auto y_pos = 0;
    for (auto const& layer : cfg_layout)
    {
        auto x_pos = 0;
        for (auto const* block : layer)
        {
            std::vector<std::string> instruction_strings;
            instruction_strings.reserve(block->size());
            for (auto const& instruction : *block)
                instruction_strings.push_back(get_instruction_string(instruction));

            auto const canvas_block = std::make_shared<utf8_text_rectangle>(
                x_pos, y_pos,
                instruction_strings, block_margin_size,
                dr, dl,
                ur, ul,
                h, v);

            canvas_blocks.emplace(block, canvas_block);
            canvas.add_shape(0, canvas_block.get());

            x_pos += canvas_block->x_size;
        }

        y_pos = canvas.height() + 1;
    }

    std::vector<std::vector<std::shared_ptr<utf8_line>>> canvas_block_transitions;

    for (auto const& [cur_block, cur_canvas_block] : canvas_blocks)
    {
        for (auto const* next_block : cur_block->successors())
        {
            auto& canvas_block_transition = canvas_block_transitions.emplace_back();

            auto const& next_canvas_block = canvas_blocks.at(next_block);

            auto const x_start = cur_canvas_block->x_pos + cur_canvas_block->x_size / 2;
            auto const y_start = cur_canvas_block->y_pos + cur_canvas_block->y_size - 1;

            auto const x_end = next_canvas_block->x_pos + next_canvas_block->x_size / 2;
            auto const y_end = next_canvas_block->y_pos;

            auto const x_diff = x_end - x_start;
            auto const y_diff = y_end - y_start;

            if (y_diff < 0)
            {
                // TODO
                continue;
            }

            auto const canvas_line_1 = std::make_shared<utf8_v_line>(
                x_start, y_start,
                y_diff - 1,
                dh, v,
                v);

            canvas_block_transition.push_back(canvas_line_1);
            canvas.add_shape(1, canvas_line_1.get());

            utf8_char canvas_line_2_start;
            utf8_char canvas_line_2_end;
            if (x_diff == 0)
            {
                canvas_line_2_start = v;
            }
            else if (x_diff < 0)
            {
                canvas_line_2_start = ul;
                canvas_line_2_end = dr;
            }
            else if (x_diff > 0)
            {
                canvas_line_2_start = ur;
                canvas_line_2_end = dl;
            }

            auto const canvas_line_2 = std::make_shared<utf8_h_line>(
                x_start, y_end - 1,
                x_diff + (x_diff >= 0 ? 1 : -1),
                canvas_line_2_start, canvas_line_2_end,
                h);

            canvas_block_transition.push_back(canvas_line_2);
            canvas.add_shape(1, canvas_line_2.get());

            auto const canvas_line_3 = std::make_shared<utf8_v_line>(
                x_end, y_end,
                1,
                uh, uh,
                v);

            canvas_block_transition.push_back(canvas_line_3);
            canvas.add_shape(1, canvas_line_3.get());
        }
    }

    std::cout << canvas.illustrate() << std::endl;
}

int main(int const argc, char const* const argv[])
{
    std::vector<std::string> const args(argv + 1, argv + argc);

    if (args.empty())
    {
        std::cerr << "Missing arguments" << std::endl;
        return 1;
    }

    auto const file_name = args.front();
    std::cout << file_name << std::endl;

    auto debugger = debugger::load(file_name);

    std::cout << std::endl;

    print_cfg(cfg(debugger));

    /* TODO */

    return 0;
}
