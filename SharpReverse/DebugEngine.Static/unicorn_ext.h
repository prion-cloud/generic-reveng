#pragma once

template <typename T>
uc_err uc_ext_mem_read(uc_engine* uc, size_t address, T& t, int offset);
template <typename T>
uc_err uc_ext_mem_read(uc_engine* uc, size_t address, T& t);

std::string uc_ext_mem_read_string_skip(uc_engine* uc, size_t address);

template <typename T>
uc_err uc_ext_mem_write(uc_engine* uc, size_t address, T t, int offset);
template <typename T>
uc_err uc_ext_mem_write(uc_engine* uc, size_t address, T t);

uint64_t uc_ext_reg_read(uc_engine* uc, int regid, uint64_t scale);
void uc_ext_reg_write(uc_engine* uc, int regid, uint64_t value);

#include "unicorn_ext_t.cpp"
