#pragma once

template <typename T>
uc_err uc_ext_mem_read(uc_engine* uc, uint64_t address, T& t, int offset);
template <typename T>
uc_err uc_ext_mem_read(uc_engine* uc, uint64_t address, T& t);

uc_err uc_ext_mem_read_string_skip(uc_engine* uc, uint64_t address, std::string& value);

template <typename T>
uc_err uc_ext_mem_write(uc_engine* uc, uint64_t address, T t, int offset);
template <typename T>
uc_err uc_ext_mem_write(uc_engine* uc, uint64_t address, T t);

// ReSharper disable once CppUnusedIncludeDirective
#include "unicorn_ext_t.cpp"
