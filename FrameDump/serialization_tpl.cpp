#include "stdafx.h"

TPL std::ofstream& operator<<=(std::ofstream& stream, const T& value)
{
    stream.write(reinterpret_cast<const char*>(&value), sizeof(T));
    return stream;
}
TPL std::ofstream& operator<<=(std::ofstream& stream, const std::vector<T>& data)
{
    if (data.size() == 0)
        return stream;

    stream.seekp(0, std::ios::end);

    const uint64_t size = data.size() * sizeof(T);

    stream <<= size;
    stream.write(reinterpret_cast<const char*>(&data.at(0)), size);

    return stream;
}

TPL std::ifstream& operator>>=(std::ifstream& stream, T& value)
{
    stream.read(reinterpret_cast<char*>(&value), sizeof(T));
    return stream;
}
TPL std::ifstream& operator>>=(std::ifstream& stream, std::vector<T>& data)
{
    uint64_t size = 0;
    stream >>= size;

    const auto count = size / sizeof(T);

    const auto load = new T[count];
    stream.read(reinterpret_cast<char*>(load), size);

    data = std::vector<T>(load, load + count);

    delete[] load;

    return stream;
}
