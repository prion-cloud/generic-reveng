#pragma once

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
    template <typename T, size_t Size>
    size_t read(std::array<T, Size>& t_arr);

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
template <typename T, size_t Size>
size_t binary_reader::read(std::array<T, Size>& t_arr)
{
    auto i = 0;

    for (; i < Size; ++i)
    {
        if (read(t_arr[i]))
            break;
    }

    return i - Size;
}
