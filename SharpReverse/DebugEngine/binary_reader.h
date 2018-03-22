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
    T read_value();
    template <typename T>
    T read_value(long offset);

    template <typename T>
    std::vector<T> read_vector(size_t size);
    template <typename T>
    std::vector<T> read_vector(size_t size, long offset);

    template <typename T, size_t Size>
    std::array<T, Size> read_array();
    template <typename T, size_t Size>
    std::array<T, Size> read_array(long offset);

    std::optional<pe_header_32> inspect_header();

    void seek() const;
    void seek(long offset) const;
    void seek(long offset, int origin) const;
};

template <typename T>
T binary_reader::read_value()
{
    auto t_ptr = static_cast<T*>(malloc(sizeof(T)));
    fread(t_ptr, sizeof(T), 1, stream_);
    T val = *t_ptr;
    free(t_ptr);
    return val;
}
template <typename T>
T binary_reader::read_value(const long offset)
{
    seek(offset);
    return read_value<T>();
}

template <typename T>
std::vector<T> binary_reader::read_vector(const size_t size)
{
    auto vec = std::vector<T>();

    for (size_t i = 0; i < size; ++i)
        vec.push_back(read_value<T>());

    return vec;
}
template <typename T>
std::vector<T> binary_reader::read_vector(const size_t size, const long offset)
{
    seek(offset);
    return read_vector<T>(size);
}

template <typename T, size_t Size>
std::array<T, Size> binary_reader::read_array()
{
    auto arr = std::array<T, Size>();

    for (auto i = 0; i < Size; ++i)
        arr[i] = read<T>();

    return arr;
}
template <typename T, size_t Size>
std::array<T, Size> binary_reader::read_array(const long offset)
{
    seek(offset);
    return read_array<T>();
}
