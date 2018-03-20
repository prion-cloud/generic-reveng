#pragma once

#include "pe_header_32.h"

class binary_reader
{
    FILE* stream_ { };
    long length_ { };

public:

    explicit binary_reader(std::string file_name);

    void close() const;

    long length() const;

    long offset() const;

    template <typename T>
    bool read(T& t);
    template <typename T>
    bool read(std::optional<T>& t_opt);
    template <typename T, size_t Count>
    size_t read(std::array<T, Count>& t_arr);
    template <typename T>
    size_t read(std::vector<T>& t_vec, size_t count);

    std::optional<pe_header_32> search_header();

    void seek() const;
    void seek(long offset) const;
    void seek(long offset, int origin) const;
};

template <typename T>
bool binary_reader::read(T& t)
{
    auto t_ptr = static_cast<T*>(malloc(sizeof(T)));
    auto res = fread(t_ptr, sizeof(T), 1, stream_) - 1;

    t = *t_ptr;

    free(t_ptr);

    return res;
}
template <typename T>
bool binary_reader::read(std::optional<T>& t_opt)
{
    T t;
    auto res = read(t);
    t_opt = t;

    return res;
}
template <typename T, size_t Count>
size_t binary_reader::read(std::array<T, Count>& t_arr)
{
    auto i = 0;
    for (; i < Count; ++i)
    {
        if (read(t_arr[i]))
            break;
    }

    return i - Count;
}
template <typename T>
size_t binary_reader::read(std::vector<T>& t_vec, const size_t count)
{
    t_vec = std::vector<T>();

    size_t i = 0;
    for (; i < count; ++i)
    {
        T t;
        if (read(t))
            break;
        t_vec.push_back(t);
    }

    return i - count;
}
