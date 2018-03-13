#pragma once

class binary_reader
{
    FILE* stream_ { };
    long length_ { };

public:

    explicit binary_reader(string file_name);

    void close() const;

    long length() const;

    long offset() const;

    template <typename T>
    size_t read(T*& t);
    template <typename T>
    size_t read(T*& t, size_t count);

    void seek() const;
    void seek(long offset) const;
    void seek(long offset, int origin) const;
};

template <typename T>
size_t binary_reader::read(T*& t)
{
    return read(t, 1);
}
template <typename T>
size_t binary_reader::read(T*& t, const size_t count)
{
    t = static_cast<T*>(malloc(sizeof(T) * count));
    return fread(t, sizeof(T), count, stream_) - count;
}
