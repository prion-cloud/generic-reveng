#pragma once

#include "../DebugEngine.Static/debugger.h"
#include "console_printer.h"

class cli_debug
{
    console_printer printer_;

    std::shared_ptr<debugger> debugger_;

    int16_t arrow_line_;
    bool bytes_shown_;

    std::map<std::string, std::function<int(std::vector<std::string>)>> commands_;

public:

    explicit cli_debug(std::shared_ptr<debugger> debugger);

    void step_into(bool registers);

    void process_command();

    void show_bytes();

private:

    void update_arrow();
    void print_next_instruction();

    std::map<std::string, std::function<int(std::vector<std::string>)>> create_commands();
};
