#pragma once

#include "../DebugEngine.Static/debugger.h"
#include "printer.h"

class cli_debug
{
    printer printer_;

    std::shared_ptr<debugger> debugger_;

    int16_t arrow_line_;

    std::map<uint64_t, int16_t> line_by_ins_;

    bool bytes_shown_;

public:

    explicit cli_debug(std::shared_ptr<debugger> debugger);

    void step_into(bool registers);

    void process_command();

    void show_bytes();

private:

    void update_arrow();
};
