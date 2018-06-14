#include "stdafx.h"

TPL std::ofstream& operator<<=(std::ofstream& stream, const T& value)
{
    stream.write(reinterpret_cast<const char*>(&value), sizeof(T));
    return stream;
}
TPL std::ofstream& operator<<=(std::ofstream& stream, const std::vector<T>& vector)
{
    stream <<= static_cast<uint8_t>(vector.size());
    
    for (const auto value : vector)
        stream <<= value;

    return stream;
}

TPL std::ifstream& operator>>=(std::ifstream& stream, T& value)
{
    stream.read(reinterpret_cast<char*>(&value), sizeof(T));
    return stream;
}
TPL std::ifstream& operator>>=(std::ifstream& stream, std::vector<T>& vector)
{
    vector = { };

    uint8_t size = 0;
    stream >>= size;

    for (auto i = 0; i < size; ++i)
    {
        T value;
        stream >>= value;
        vector.push_back(value);
    }

    return stream;
}
