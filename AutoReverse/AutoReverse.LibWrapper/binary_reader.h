#pragma once

class binary_reader
{
    FILE* stream_ { };
    size_t length_ { };

public:

    explicit binary_reader(const char* file_name);

    void close() const;

    size_t length() const;

    size_t offset() const;

    template <typename T>
    int read(T*& t);
    template <typename T>
    size_t read(T*& t, size_t count);

    void seek(long offset) const;
    void seek(long offset, int origin) const;
};

template <typename T>
int binary_reader::read(T*& t)
{
    return read(t, 1);
}
template <typename T>
size_t binary_reader::read(T*& t, const size_t count)
{
    return fread(t, sizeof(T), count, stream_) - count;
}
