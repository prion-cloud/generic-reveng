#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include <scout/cfg.hpp>
#include <scout/debugger.hpp>

#include <unimage/utf8_canvas.hpp>

umg::utf8_char const h("\u2500"/* │ */);
umg::utf8_char const v("\u2502"/* ─ */);

umg::utf8_char const ur("\u2514"/* └ */);
umg::utf8_char const ul("\u2518"/* ┘ */);
umg::utf8_char const dr("\u250C"/* ┌ */);
umg::utf8_char const dl("\u2510"/* ┐ */);

umg::utf8_char const uh("\u2534"/* ┴ */);
umg::utf8_char const dh("\u252C"/* ┬ */);

std::string get_instruction_string(machine_instruction const& instruction)
{
    std::ostringstream oss_instruction;
    oss_instruction << std::hex << instruction.address << ' ';

    auto const disassembly = instruction.disassemble();

    std::optional<std::string> color;

    if (disassembly.belongs_to(CS_GRP_CALL) || disassembly.belongs_to(CS_GRP_RET))
        color = "\x1B[38;2;0;148;255m";

    if (disassembly.belongs_to(CS_GRP_JUMP))
        color = "\x1B[38;2;255;204;33m";

    if (disassembly.belongs_to(CS_GRP_INT))
        color = "\x1B[38;2;255;33;33m";

    if (color)
        oss_instruction << *color;

    oss_instruction << disassembly->mnemonic;

    std::string const operands_string = disassembly->op_str;
    if (operands_string.size() > 0)
    {
        oss_instruction << ' ' << std::regex_replace(
            operands_string,
            std::regex("0x([\\da-f]+)"), "$1");
    }

    if (color)
        oss_instruction << "\x1B[0m";

    return oss_instruction.str();
}

void print_cfg(cfg const& cfg)
{
    auto constexpr width = 200;

    auto constexpr block_layer = 0;

    auto constexpr straight_transition_layer = 1;
    auto constexpr curved_transition_layer = 2;

    umg::utf8_canvas canvas(width);

    std::unordered_map<cfg::block const*, umg::utf8_text_rectangle*> block_views;

    for (auto const& block : cfg)
    {
        std::vector<std::string> instruction_strings;
        instruction_strings.reserve(block->size());
        for (auto const& instruction : *block)
            instruction_strings.push_back(get_instruction_string(instruction));

        auto block_view = std::make_unique<umg::utf8_text_rectangle>(
            0, 0, instruction_strings, 1, dr, dl, ur, ul, h, v);

        block_views.emplace(block.get(), block_view.get());

        canvas.add_shape(block_layer, std::move(block_view));
    }

    auto const cfg_columns = cfg.get_layout();

    size_t n_rows = 0;

    auto column_x_pos = 0;
    for (size_t column = 0; column < cfg_columns.size(); ++column)
    {
        auto const& cfg_column = cfg_columns.at(column);

        auto column_x_size = 0;
        for (auto const& [row, block] : cfg_column)
        {
            column_x_size = std::max(column_x_size,
                block_views.at(block)->x_size);

            n_rows = std::max(n_rows, row + 1);
        }

        for (auto const& column_block_entry : cfg_column)
        {
            auto* const block_layout = block_views.at(column_block_entry.second);

            block_layout->x_pos =
                column_x_pos +
                column_x_size / 2 - block_layout->x_size / 2;
        }

        column_x_pos += column_x_size;
    }

    std::unordered_map<cfg::block const*, std::pair<int, std::pair<int, int>>> nipple_map;

    auto row_y_pos = 0;
    for (size_t row = 0; row < n_rows; ++row)
    {
        auto row_y_size = 0;
        for (size_t column = 0; column < cfg_columns.size(); ++column)
        {
            auto const& cfg_column = cfg_columns.at(column);

            auto const search = cfg_column.find(row);
            if (search == cfg_column.end())
                continue;

            auto* const block_layout = block_views.at(search->second);

            block_layout->y_pos = row_y_pos;

            nipple_map.emplace(
                search->second,
                std::make_pair(
                    block_layout->x_pos + block_layout->x_size / 2,
                    std::make_pair(
                        block_layout->y_pos,
                        block_layout->y_pos + block_layout->y_size - 1)));

            row_y_size = std::max(row_y_size, block_layout->y_size);
        }

        row_y_pos += row_y_size + 1;
    }

    for (auto const& cur_block : cfg)
    {
        auto const& cur_block_view = block_views.at(cur_block.get());

        for (auto const* const next_block : cur_block->successors)
        {
            auto const& next_block_view = block_views.at(next_block);

            auto const x_start = cur_block_view->x_pos + cur_block_view->x_size / 2;
            auto const y_start = cur_block_view->y_pos + cur_block_view->y_size - 1;

            auto const x_end = next_block_view->x_pos + next_block_view->x_size / 2;
            auto const y_end = next_block_view->y_pos;

            auto const x_diff = x_end - x_start;
            auto const y_diff = y_end - y_start;

            if (y_diff < 0)
            {
                // TODO
                continue;
            }

            auto transition_view_1 = std::make_unique<umg::utf8_v_line>(
                x_start, y_start, y_diff - 1,
                dh, v, v);

            umg::utf8_char transition_view_2_start;
            umg::utf8_char transition_view_2_end;
            if (x_diff == 0)
            {
                transition_view_2_start = v;
            }
            else if (x_diff < 0)
            {
                transition_view_2_start = ul;
                transition_view_2_end = dr;
            }
            else if (x_diff > 0)
            {
                transition_view_2_start = ur;
                transition_view_2_end = dl;
            }

            auto transition_view_2 = std::make_unique<umg::utf8_h_line>(
                x_start, y_end - 1, x_diff + (x_diff >= 0 ? 1 : -1),
                transition_view_2_start, transition_view_2_end, h);

            auto transition_view_3 = std::make_unique<umg::utf8_v_line>(
                x_end, y_end, 1,
                uh, uh, v);

            auto const layer = x_diff == 0
                ? straight_transition_layer
                : curved_transition_layer;

            canvas.add_shape(layer, std::move(transition_view_1));
            canvas.add_shape(layer, std::move(transition_view_2));
            canvas.add_shape(layer, std::move(transition_view_3));
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
