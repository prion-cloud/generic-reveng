#include "stdafx.h"

template <typename T>
uc_err uc_ext_mem_read(uc_engine* uc, const size_t address, T& t, const int offset)
{
    const auto size = sizeof(T);
    return uc_mem_read(uc, address + offset * size, &t, size);
}
template <typename T>
uc_err uc_ext_mem_read(uc_engine* uc, const size_t address, T& t)
{
    return uc_ext_mem_read(uc, address, t, 0);
}

template <typename T>
uc_err uc_ext_mem_write(uc_engine* uc, const size_t address, T t, const int offset)
{
    const auto size = sizeof(T);
    return uc_mem_write(uc, address + offset * size, &t, size);
}
template <typename T>
uc_err uc_ext_mem_write(uc_engine* uc, const size_t address, T t)
{
    return uc_ext_mem_write(uc, address, t, 0);
}
