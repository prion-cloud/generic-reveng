#pragma once

template <typename T>
uc_err uc_mem_read(uc_engine* uc, uint64_t address, T& t); // Reads generic data.
template <typename T>
uc_err uc_mem_read(uc_engine* uc, uint64_t address, int offset, T& t); // Reads generic data on a specified offset.

uc_err uc_mem_read_string(uc_engine* uc, uint64_t address, std::string& s); // Reads a null-terminated string of at least one character (skips preceding zeros).

template <typename T>
uc_err uc_mem_write(uc_engine* uc, uint64_t address, T t); // Writes generic data.
template <typename T>
uc_err uc_mem_write(uc_engine* uc, uint64_t address, int offset, T t); // Writes generic data on a specified offset.

uc_err uc_initialize_registers(uc_engine* uc, size_t stack_pointer, size_t entry_point);

uc_err uc_initialize_section(uc_engine* uc, std::vector<char> bytes, size_t address);

// ---------------

template <typename T>
uc_err uc_mem_read(uc_engine* uc, const uint64_t address, T& t)
{
    return uc_mem_read(uc, address, 0, t);
}
template <typename T>
uc_err uc_mem_read(uc_engine* uc, const uint64_t address, const int offset, T& t)
{
    const auto size = sizeof(T);
    return uc_mem_read(uc, address + offset * size, &t, size);
}

template <typename T>
uc_err uc_mem_write(uc_engine* uc, const uint64_t address, T t)
{
    return uc_mem_write(uc, address, 0, t);
}
template <typename T>
uc_err uc_mem_write(uc_engine* uc, const uint64_t address, const int offset, T t)
{
    const auto size = sizeof(T);
    return uc_mem_write(uc, address + offset * size, &t, size);
}
