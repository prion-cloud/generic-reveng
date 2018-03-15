#pragma once

#include "binary_reader.h"
#include "debug_32.h"
#include "pe_header.h"

class debugger
{
    binary_reader reader_;

    std::optional<pe_header> header_ { };

    csh cs_handle_ { };
    uc_engine* uc_handle_ { };

public:

    explicit debugger(std::string file_name);

    void close();

    debug_32 debug();
};
