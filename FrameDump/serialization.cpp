#include "stdafx.h"

#include "serialization.h"

size_t get_size(std::ifstream& stream)
{
    const auto pos = stream.tellg();

    stream.seekg(0, std::ios::end);
    const size_t size = stream.tellg();

    stream.seekg(pos, std::ios::beg);

    return size;
}
