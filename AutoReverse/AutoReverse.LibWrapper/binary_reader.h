// binary_reader.h

#pragma once

#include <cstdio>

class binary_reader
{
    FILE* stream_ { };
    size_t length_;

public:

    explicit binary_reader(const char* file_name);

    void close() const;

    size_t length() const;

    long offset() const;

    template <typename T>
    int read(T& t);
    template <typename T>
    int read(T*& t, int count);

    void seek(long offset) const;
    void seek(long offset, int origin) const;
};

template <typename T>
int binary_reader::read(T& t)
{
    return read(t, 1);
}
template <typename T>
int binary_reader::read(T*& t, const int count)
{
    return fread(t, sizeof(T), count, stream_) - count;
}
