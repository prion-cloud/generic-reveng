#pragma once

#include "debug_32.h"

class debugger
{
    csh cs_handle_ { };
    uc_engine* uc_handle_ { };

public:

    explicit debugger(std::string file_name);

    void close();

    debug_32 debug() const;
};
