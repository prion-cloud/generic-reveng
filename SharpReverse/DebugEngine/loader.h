#pragma once

struct debug_info
{
    csh cs;
    uc_engine* uc;

    size_t stack_pointer;
    size_t entry_point;
};

void load_pe(std::string file_name, csh& cs, uc_engine*& uc);

void load_bytes(std::vector<char> bytes, csh& cs, uc_engine*& uc);
