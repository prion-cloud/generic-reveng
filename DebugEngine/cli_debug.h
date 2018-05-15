#pragma once

#include "../DebugEngine.Static/debugger.h"

class cli_debug
{
    HANDLE h_console_;

    std::unique_ptr<debugger> debugger_;

    std::vector<debug_trace_entry> trace_;
    debug_trace_entry cur_trace_entry_;

    bool endl_;

    size_t erase_size_;

public:

    explicit cli_debug(HANDLE h_console, std::string file_name);

    void reset();

    void step_into(bool registers);

    void process_command();

private:
    
    void print_next_instruction();

    void update_cursor(bool visible) const;
};
