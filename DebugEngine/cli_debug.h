#pragma once

#include "../DebugEngine.Static/debugger.h"

class cli_debug
{
    HANDLE h_console_;

    std::unique_ptr<debugger> debugger_;

    int16_t arrow_line_;

    std::map<uint64_t, int16_t> line_by_ins_;
    std::map<int16_t, instruction> ins_by_line_;

    bool bytes_shown_;

public:

    explicit cli_debug(HANDLE h_console, std::string file_name);

    void step_into(bool registers);

    void process_command();

    void show_bytes();

private:

    void update_arrow();

    void print_instruction(instruction instruction);
    void print_next_instruction();

    void reprint_instruction(int16_t line, size_t erase_size);

    void print_error(std::string message);

    void update_cursor(bool visible) const;

    int16_t get_cursor() const;
    void set_cursor(int16_t line) const;

    // Returns top line.
    int16_t floor_cursor() const;
};
