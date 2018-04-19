#pragma once

/**
 * \brief Unicorn Extension: Reads generic data at a specific index in memory.
 */
template <typename T>
uc_err uc_ext_mem_read(uc_engine* uc, uint64_t address, T& t, int index);
/**
 * \brief Unicorn Extension: Reads generic data in memory.
 */
template <typename T>
uc_err uc_ext_mem_read(uc_engine* uc, uint64_t address, T& t);

/**
 * \brief Unicorn Extension: Reads a null-terminated string in memory.
 */
uc_err uc_ext_mem_read_string(uc_engine* uc, uint64_t address, std::string& value);

/**
 * \brief Unicorn Extension: Writes generic data at a specific index in memory.
 */
template <typename T>
uc_err uc_ext_mem_write(uc_engine* uc, uint64_t address, T t, int index);
/**
 * \brief Unicorn Extension: Writes generic data in memory.
 */
template <typename T>
uc_err uc_ext_mem_write(uc_engine* uc, uint64_t address, T t);

// ReSharper disable once CppUnusedIncludeDirective
#include "unicorn_ext_t.cpp"
