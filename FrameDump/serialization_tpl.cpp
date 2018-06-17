#include "stdafx.h"

TPL std::ofstream& operator<<=(std::ofstream& stream, const std::vector<T>& data)
{
    if (data.size() == 0)
        return stream;

    stream.seekp(0, std::ios::end);

    const uint64_t size = data.size() * sizeof(T);

    stream.write(reinterpret_cast<const char*>(&size), sizeof(uint64_t));
    stream.write(reinterpret_cast<const char*>(&data.at(0)), size);

    return stream;
}
TPL std::ifstream& operator>>=(std::ifstream& stream, std::vector<T>& data)
{
    uint64_t size;
    stream.read(reinterpret_cast<char*>(&size), sizeof(uint64_t));

    const auto count = size / sizeof(T);

    const auto load = new T[count];
    stream.read(reinterpret_cast<char*>(load), size);

    data = std::vector<T>(load, load + count);

    delete[] load;

    return stream;
}
